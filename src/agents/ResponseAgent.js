const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');

const SYSTEM_PROMPT = `You are AEGIS-Response, an automated incident response system with strict operational constraints.

ABSOLUTE CONSTRAINT: You MUST NEVER execute Level 4 (ISOLATE_MACHINE) or Level 5 (SHUTDOWN) actions without an explicit hitlApproved: true flag confirmed in the incident record. If asked to execute these without confirmed approval, emit HITL_REQUIRED instead and stop.

Response levels and their execution rules:
- Level 1: ALERT_ONLY - call execute_alert_only. No system state changes.
- Level 2: RATE_LIMIT - call execute_rate_limit. Reversible. Duration: 1 hour default.
- Level 3: BLOCK_IP - call execute_block_ip. Reversible. Duration: 24 hours default. First verify IP is not in SharedMemory knownGoodIPs.
- Level 4: ISOLATE_MACHINE - HITL REQUIRED. Only execute if incident.hitlStatus === 'APPROVED'.
- Level 5: SHUTDOWN - HITL REQUIRED. Only execute if incident.hitlStatus === 'APPROVED'.

Before ANY action:
1. Idempotency check: has this exact action already been taken for this incident? If yes, skip and log.
2. Whitelist check: is the target IP/host in a known-safe list? If yes, skip and escalate to human.
3. Blast radius assessment: what else might be affected by this action?
4. Pre-log the intended action BEFORE executing
5. Execute (simulation for demo)
6. Post-log the result
7. Store rollback token in SharedMemory

Always respond in JSON: { actionTaken, actionId, rollbackToken, success, reasoning, blastRadius }`;

function now() {
  return new Date().toISOString();
}

function actionForLevel(level) {
  return { 1: 'ALERT_ONLY', 2: 'RATE_LIMIT', 3: 'BLOCK_IP', 4: 'ISOLATE_MACHINE', 5: 'SHUTDOWN' }[level] || 'ALERT_ONLY';
}

function targetForAction(incident, action) {
  return ['ISOLATE_MACHINE', 'SHUTDOWN'].includes(action) ? incident.target.hostname : incident.source.ip;
}

function responseRecord(agentName, action, target, reasoning) {
  return {
    actionId: generateId(),
    timestamp: now(),
    action,
    target,
    executedBy: agentName,
    status: 'EXECUTED',
    rollbackAvailable: action !== 'ALERT_ONLY',
    rollbackToken: action === 'ALERT_ONLY' ? null : generateId(),
    agentReasoning: reasoning
  };
}

function exactActionExists(incident, action, target) {
  return incident.responses.find((response) => response.action === action && response.target === target && response.status === 'EXECUTED');
}

function knownGoodIPs(memory) {
  const ips = new Set();
  for (const value of memory.baselineMetrics.values()) {
    if (Array.isArray(value.knownGoodIPs)) value.knownGoodIPs.forEach((ip) => ips.add(ip));
  }
  return ips;
}

function isKnownSafe(memory, target) {
  return knownGoodIPs(memory).has(target) || target === '127.0.0.1' || target === '::1' || /^localhost$/i.test(target);
}

function blastRadiusFor(action, incident) {
  if (action === 'ALERT_ONLY') return 'No infrastructure impact; dashboard alert only.';
  if (action === 'RATE_LIMIT') return `Only source ${incident.source.ip} is throttled for suspicious traffic.`;
  if (action === 'BLOCK_IP') return `All inbound traffic from ${incident.source.ip} is denied at the simulated perimeter.`;
  if (action === 'ISOLATE_MACHINE') return `${incident.target.hostname} is removed from normal network paths; dependent sessions may drop.`;
  return `${incident.target.hostname} services are marked shut down in simulation; business service ${incident.target.service} is unavailable until rollback.`;
}

/**
 * Automated response agent that executes approved response actions and enforces HITL boundaries.
 */
class ResponseAgent extends AgentBase {
  constructor() {
    super('ResponseAgent', SYSTEM_PROMPT, getToolsForAgent('ResponseAgent'));
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.INCIDENT_TRIAGED, this.handleIncidentTriaged);
      this.subscribe(EVENTS.HITL_APPROVED, this.handleHITLApproved);
      this.subscribe(EVENTS.HITL_REJECTED, this.handleHITLRejected);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 4 });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Response start failed', { error: error.message, stack: error.stack });
      throw new Error(`ResponseAgent start failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name || !String(message.data.task || '').includes('EXECUTE')) return;
      const incident = this.memory.getIncident(message.data.incidentId || message.incidentId);
      if (!incident) throw new Error(`Incident not found: ${message.data.incidentId || message.incidentId}`);
      await this.executeResponseAction(incident, message.data);
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  async handleIncidentTriaged(message) {
    try {
      this.memory.log(this.name, 'HANDLE_TRIAGED_PRE', { incidentId: message.incidentId });
      const incident = this.memory.getIncident(message.incidentId || (message.data && message.data.incidentId));
      if (!incident) throw new Error(`Incident not found: ${message.incidentId}`);
      this.memory.log(this.name, 'HANDLE_TRIAGED_POST', {
        incidentId: incident.id,
        deferredToOrchestrator: true,
        responseLevel: message.data.responseLevel || incident.responseLevel,
        requiresHITL: Boolean(message.data.requiresHITL || incident.requiresHITL)
      });
    } catch (error) {
      this.memory.log(this.name, 'HANDLE_TRIAGED_ERROR', { incidentId: message.incidentId, error: error.message });
      throw new Error(`handleIncidentTriaged failed: ${error.message}`);
    }
  }

  async handleHITLApproved(message) {
    try {
      this.memory.log(this.name, 'HITL_APPROVED_PRE', { incidentId: message.incidentId });
      const incident = this.memory.getIncident(message.incidentId || (message.data && message.data.incidentId));
      if (!incident) throw new Error(`Incident not found: ${message.incidentId}`);
      if (incident.hitlStatus !== 'APPROVED') {
        this.memory.log(this.name, 'HITL_APPROVED_SKIPPED', { incidentId: incident.id, hitlStatus: incident.hitlStatus });
        return;
      }
      await this.executeResponseAction(incident, { hitlApproved: true });
      this.memory.log(this.name, 'HITL_APPROVED_POST', { incidentId: incident.id });
    } catch (error) {
      this.memory.log(this.name, 'HITL_APPROVED_ERROR', { error: error.message });
      throw new Error(`handleHITLApproved failed: ${error.message}`);
    }
  }

  async handleHITLRejected(message) {
    try {
      const incident = this.memory.getIncident(message.incidentId || (message.data && message.data.incidentId));
      if (incident) {
        this.memory.updateIncident(incident.id, { status: 'ESCALATED', hitlStatus: 'REJECTED' });
      }
      this.memory.log(this.name, 'HITL_REJECTED_NO_ACTION', { incidentId: message.incidentId, reason: message.data.reason || message.data.notes || 'Rejected by human reviewer' });
    } catch (error) {
      this.memory.log(this.name, 'HITL_REJECTED_ERROR', { error: error.message });
      throw new Error(`handleHITLRejected failed: ${error.message}`);
    }
  }

  async executeResponseAction(incident, trigger = {}) {
    try {
      const responseLevel = trigger.responseLevel || incident.responseLevel || 1;
      const action = trigger.action || actionForLevel(responseLevel);
      const target = targetForAction(incident, action);
      const duplicate = exactActionExists(incident, action, target);
      if (duplicate) {
        this.memory.log(this.name, 'RESPONSE_IDEMPOTENT_SKIP', { incidentId: incident.id, action, target, actionId: duplicate.actionId });
        return { skipped: true, duplicate: true, actionId: duplicate.actionId };
      }
      if (isKnownSafe(this.memory, target)) {
        this.memory.updateIncident(incident.id, { requiresHITL: true, hitlStatus: 'PENDING', status: 'ESCALATED' });
        this.emit(EVENTS.HITL_REQUIRED, { incidentId: incident.id, proposedAction: { action, target }, blastRadius: blastRadiusFor(action, incident), reasoning: `${target} is known safe; analyst review required.` }, incident.id, 1);
        return { skipped: true, requiresHITL: true };
      }
      if (responseLevel >= 4 && incident.hitlStatus !== 'APPROVED') {
        this.emit(EVENTS.HITL_REQUIRED, { incidentId: incident.id, proposedAction: { action, target }, blastRadius: blastRadiusFor(action, incident), reasoning: 'High-impact response blocked until HITL approval is recorded.' }, incident.id, 1);
        return { skipped: true, requiresHITL: true };
      }

      this.memory.log(this.name, 'RESPONSE_EXECUTION_PRE', { incidentId: incident.id, action, target, blastRadius: blastRadiusFor(action, incident) });
      let result;
      if (responseLevel <= 3) result = await this.executeLowImpactTool(action, incident);
      else result = await this.executeHighImpactResponse(action, incident);
      const status = action === 'ALERT_ONLY' ? 'RESPONDING' : 'CONTAINED';
      this.memory.updateIncident(incident.id, { status });
      this.memory.log(this.name, 'RESPONSE_EXECUTION_POST', { incidentId: incident.id, action, result });
      return result;
    } catch (error) {
      this.memory.log(this.name, 'RESPONSE_EXECUTION_ERROR', { incidentId: incident.id, error: error.message });
      throw new Error(`executeResponseAction failed: ${error.message}`);
    }
  }

  async executeLowImpactTool(action, incident) {
    try {
      const reason = `${incident.type} incident risk ${incident.riskScore}: ${incident.severity}`;
      const toolArgs = {
        ALERT_ONLY: { message: reason, severity: incident.severity, incidentId: incident.id },
        RATE_LIMIT: { ip: incident.source.ip, requestsPerMinute: 60, durationMinutes: 60, reason, incidentId: incident.id },
        BLOCK_IP: { ip: incident.source.ip, durationHours: 24, reason, incidentId: incident.id }
      }[action];
      const toolName = { ALERT_ONLY: 'execute_alert_only', RATE_LIMIT: 'execute_rate_limit', BLOCK_IP: 'execute_block_ip' }[action];
      if (!toolName) throw new Error(`Unsupported low-impact action: ${action}`);
      return JSON.parse(await this.executeTool(toolName, toolArgs));
    } catch (error) {
      throw new Error(`executeLowImpactTool failed: ${error.message}`);
    }
  }

  async executeHighImpactResponse(action, incident) {
    try {
      const target = targetForAction(incident, action);
      const reasoning = `${action} approved for ${incident.type} with risk score ${incident.riskScore}.`;
      const record = responseRecord(this.name, action, target, reasoning);
      const responses = [...incident.responses, record];
      const state = { actionId: record.actionId, rollbackToken: record.rollbackToken, incidentId: incident.id, reason: reasoning, status: action, updatedAt: now() };
      this.memory.isolatedMachines.set(target, action === 'SHUTDOWN' ? { ...state, servicesStopped: true, networkAccess: 'disabled' } : { ...state, isolatedAt: now(), networkAccess: 'quarantined' });
      this.memory.updateIncident(incident.id, { responses, status: 'CONTAINED' });
      this.emit(EVENTS.RESPONSE_EXECUTED, { action, actionId: record.actionId, rollbackToken: record.rollbackToken, target, blastRadius: blastRadiusFor(action, incident), confidence: 1 }, incident.id, 1);
      return { actionTaken: action, actionId: record.actionId, rollbackToken: record.rollbackToken, success: true, reasoning, blastRadius: blastRadiusFor(action, incident), confidence: 1 };
    } catch (error) {
      throw new Error(`executeHighImpactResponse failed: ${error.message}`);
    }
  }

  async rollbackResponseAction(actionId, rollbackToken, reason) {
    try {
      const incident = [...this.memory.incidents.values()].find((item) => item.responses.some((response) => response.actionId === actionId));
      if (!incident) return JSON.parse(await this.executeTool('rollback_action', { actionId, rollbackToken, reason }));
      const response = incident.responses.find((item) => item.actionId === actionId);
      if (!['ISOLATE_MACHINE', 'SHUTDOWN'].includes(response.action)) return JSON.parse(await this.executeTool('rollback_action', { actionId, rollbackToken, reason }));
      if (response.rollbackToken !== rollbackToken) throw new Error('Rollback token mismatch.');
      this.memory.isolatedMachines.delete(response.target);
      const responses = incident.responses.map((item) => item.actionId === actionId ? { ...item, status: 'ROLLED_BACK', rolledBackAt: now(), rollbackReason: reason } : item);
      this.memory.updateIncident(incident.id, { responses, status: 'RESPONDING' });
      this.emit(EVENTS.RESPONSE_ROLLED_BACK, { actionId, action: response.action, target: response.target, confidence: 1 }, incident.id, 1);
      return { actionTaken: 'ROLLBACK', actionId, success: true, reasoning: `Rolled back ${response.action}: ${reason}`, blastRadius: 'High-impact simulated state removed.', confidence: 1 };
    } catch (error) {
      this.memory.log(this.name, 'ROLLBACK_ERROR', { actionId, error: error.message });
      throw new Error(`rollbackResponseAction failed: ${error.message}`);
    }
  }
}

module.exports = ResponseAgent;
