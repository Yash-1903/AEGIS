const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { combineConfidences } = require('../core/ConfidenceEngine');

const SYSTEM_PROMPT = `You are AEGIS-Triage, a senior SOC analyst responsible for incident prioritization and response level assignment.

Risk scoring methodology (APPLY EXACTLY):
Base score (1-10):
- CRITICAL threat severity: 8-10 base
- HIGH: 6-7 base
- MEDIUM: 4-5 base
- LOW: 1-3 base

Modifiers (additive):
- Lateral movement confirmed: +2
- Active data exfiltration: +2
- Insider threat indicators: +1.5
- Active CVE exploit (in CISA KEV): +1.5
- CRITICAL target system: +1
- Isolated incident, no lateral movement: -1
- Known pen test / scanner activity: -2
- Sandboxed/test environment target: -1.5

Response level mapping (APPLY EXACTLY):
- Level 1 (ALERT_ONLY): Risk 1-3 - notify analyst, no automated action
- Level 2 (RATE_LIMIT): Risk 4-5, confidence >= 0.6
- Level 3 (BLOCK_IP): Risk 6-7, confidence >= 0.75
- Level 4 (ISOLATE_MACHINE): Risk 8-9, confidence >= 0.8 - ALWAYS requiresHITL: true
- Level 5 (SHUTDOWN): Risk 10, confidence >= 0.9 - ALWAYS requiresHITL: true

CRITICAL: You MUST set requiresHITL: true for levels 4 and 5 WITHOUT EXCEPTION.

Respond in JSON: { riskScore, responseLevel, severity, requiresHITL, reasoning, businessImpact }`;

function hasCisaKev(incident) {
  return Boolean(incident.enrichedIntel && incident.enrichedIntel.feedMatches
    && incident.enrichedIntel.feedMatches.some((match) => match.source === 'CISA KEV' || match.ransomwareUse === 'Known'));
}

function hasLateralMovement(incident) {
  return incident.type === 'LATERAL_MOVEMENT' || incident.rawEvidence.some((line) => /(SMB|RDP|port (445|3389)|lateral)/i.test(line));
}

function hasExfiltration(incident) {
  return incident.type === 'DATA_EXFILTRATION' || incident.rawEvidence.some((line) => /(exfil|CANARY|DNS.*size=|large transfer)/i.test(line));
}

function hasInsiderSignal(incident) {
  return incident.rawEvidence.some((line) => /(employee|insider|vpn.*internal|terminated user)/i.test(line));
}

function proposedAction(responseLevel) {
  const actions = { 1: 'ALERT_ONLY', 2: 'RATE_LIMIT', 3: 'BLOCK_IP', 4: 'ISOLATE_MACHINE', 5: 'SHUTDOWN' };
  return actions[responseLevel] || 'ALERT_ONLY';
}

function enforceHITL(responseLevel, requiresHITL) {
  return responseLevel >= 4 || Boolean(requiresHITL);
}

function businessImpact(incident, riskScore) {
  if (riskScore >= 8) {
    return `${incident.target.hostname} is high risk; containment may affect business service ${incident.target.service}.`;
  }
  if (riskScore >= 4) {
    return `Targeted service ${incident.target.service} requires analyst visibility but automated action has limited blast radius.`;
  }
  return 'Low operational impact; monitoring and notification are sufficient.';
}

/**
 * SOC triage agent responsible for risk scoring, response-level assignment, and HITL flagging.
 */
class TriageAgent extends AgentBase {
  constructor() {
    super('TriageAgent', SYSTEM_PROMPT, getToolsForAgent('TriageAgent'));
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.INTEL_ENRICHED, this.triageIncident);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 2 });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Triage start failed', { error: error.message, stack: error.stack });
      throw new Error(`TriageAgent start failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name || message.data.task !== 'TRIAGE_INCIDENT') return;
      await this.triageIncident(message);
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  async triageIncident(message) {
    try {
      this.memory.log(this.name, 'TRIAGE_PRE', { incidentId: message.incidentId, messageId: message.messageId });
      if (message.eventType === EVENTS.INTEL_ENRICHED) {
        this.memory.log(this.name, 'TRIAGE_DEFERRED_TO_ORCHESTRATOR', {
          incidentId: message.incidentId,
          messageId: message.messageId
        });
        return;
      }
      const incidentId = message.incidentId || (message.data && message.data.incidentId);
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);

      const scoringArgs = {
        threatSeverity: incident.severity,
        targetCriticality: incident.target.criticality,
        confidence: incident.confidence,
        hasActiveExploit: hasCisaKev(incident),
        isInsiderThreat: hasInsiderSignal(incident),
        lateralMovementDetected: hasLateralMovement(incident),
        dataExfiltrationInProgress: hasExfiltration(incident)
      };
      const riskResult = await this.think('Calculate risk score using calculate_risk_score. Return JSON only.', scoringArgs);
      const riskScore = Number.isFinite(Number(riskResult.riskScore)) ? Math.max(1, Math.min(10, Math.round(Number(riskResult.riskScore)))) : incident.riskScore || 1;
      const levelResult = await this.think('Determine response level using determine_response_level. Return JSON only.', {
        riskScore,
        incidentType: incident.type,
        targetCriticality: incident.target.criticality,
        confidence: incident.confidence
      });
      const responseLevel = Number.isFinite(Number(levelResult.responseLevel)) ? Math.max(1, Math.min(5, Math.round(Number(levelResult.responseLevel)))) : 1;
      const requiresHITL = enforceHITL(responseLevel, levelResult.requiresHITL);
      const confidence = combineConfidences([incident.confidence, riskResult.confidence || incident.confidence, levelResult.confidence || incident.confidence]);
      const proposed = {
        action: proposedAction(responseLevel),
        responseLevel,
        target: responseLevel >= 4 ? incident.target.hostname : incident.source.ip,
        riskScore
      };

      const updatedIncident = this.memory.updateIncident(incident.id, {
        status: requiresHITL ? 'ESCALATED' : 'RESPONDING',
        riskScore,
        responseLevel,
        severity: riskResult.severity || incident.severity,
        requiresHITL,
        hitlStatus: requiresHITL ? 'PENDING' : 'NOT_REQUIRED',
        agentNotes: [...(incident.agentNotes || []), {
          agent: this.name,
          note: `Risk ${riskScore}, response level ${responseLevel}, HITL ${requiresHITL ? 'required' : 'not required'}.`,
          timestamp: new Date().toISOString()
        }]
      });
      this.emit(EVENTS.INCIDENT_TRIAGED, {
        incidentId: incident.id,
        riskScore,
        responseLevel,
        severity: updatedIncident.severity,
        requiresHITL,
        proposedAction: proposed,
        businessImpact: businessImpact(updatedIncident, riskScore),
        reasoning: levelResult.reasoning || riskResult.reasoning || 'Incident triage completed.'
      }, incident.id, confidence);
      this.memory.log(this.name, 'TRIAGE_POST', { incidentId: incident.id, riskScore, responseLevel, requiresHITL });
    } catch (error) {
      this.memory.log(this.name, 'TRIAGE_ERROR', { incidentId: message.incidentId, error: error.message });
      this.logger.error('triageIncident failed', { error: error.message, stack: error.stack });
      throw new Error(`triageIncident failed: ${error.message}`);
    }
  }
}

module.exports = TriageAgent;
