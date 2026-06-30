const { EVENTS } = require('../constants/events');

function lazySharedMemory() {
  return require('../core/SharedMemory').getInstance();
}

function lazyGenerateId() {
  return require('../utils/idGenerator').generateId();
}

function now() {
  return new Date().toISOString();
}

function assertString(value, name) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string.`);
  }
  return value.trim();
}

function assertPositiveNumber(value, name, fallback = null) {
  const resolved = value === undefined || value === null ? fallback : value;
  const numeric = Number(resolved);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`${name} must be a positive number.`);
  }
  return numeric;
}

function assertIp(ip) {
  const value = assertString(ip, 'ip');
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    throw new Error(`Invalid IPv4 address: ${value}`);
  }
  return value;
}

function resolveMemory(context) {
  return context.memory || lazySharedMemory();
}

function preLog(memory, agentName, action, data) {
  memory.log(agentName, `${action}_PRE`, data);
}

function postLog(memory, agentName, action, data) {
  memory.log(agentName, `${action}_POST`, data);
}

function emit(context, eventType, incidentId, data, reasoning) {
  if (!context.bus) {
    return false;
  }
  return context.bus.emit(eventType, {
    messageId: lazyGenerateId(),
    timestamp: now(),
    source: context.agentName || 'ResponseExecutorTool',
    eventType,
    incidentId,
    confidence: typeof data.confidence === 'number' ? data.confidence : 1,
    data,
    reasoning
  });
}

function responseRecord(actionId, action, target, rollbackToken, rollbackAvailable, reasoning, agentName) {
  return {
    actionId,
    timestamp: now(),
    action,
    target,
    executedBy: agentName || 'ResponseExecutorTool',
    status: 'EXECUTED',
    rollbackAvailable,
    rollbackToken,
    agentReasoning: reasoning
  };
}

function statusAfterAction(action) {
  return action === 'ALERT_ONLY' ? 'RESPONDING' : 'CONTAINED';
}

function updateIncidentResponses(memory, incidentId, record) {
  const incident = memory.getIncident(incidentId);
  if (!incident) {
    throw new Error(`Incident not found: ${incidentId}`);
  }
  const existing = incident.responses.find((item) => item.action === record.action && item.target === record.target && item.status === 'EXECUTED');
  if (existing) {
    return { incident, record: existing, duplicate: true };
  }
  const responses = [...incident.responses, record];
  return {
    incident: memory.updateIncident(incidentId, { responses, status: statusAfterAction(record.action) }),
    record,
    duplicate: false
  };
}

function storeAlert(memory, alert) {
  if (!Array.isArray(memory.alerts)) {
    memory.alerts = [];
  }
  memory.alerts.unshift(alert);
  if (memory.alerts.length > 1000) {
    memory.alerts.pop();
  }
}

function findAction(memory, actionId) {
  for (const incident of memory.incidents.values()) {
    const index = incident.responses.findIndex((response) => response.actionId === actionId);
    if (index !== -1) {
      return { incident, index, active: true };
    }
  }
  for (const incident of memory.incidentHistory) {
    const index = incident.responses.findIndex((response) => response.actionId === actionId);
    if (index !== -1) {
      return { incident, index, active: false };
    }
  }
  return null;
}

function rollbackState(memory, action) {
  if (action.action === 'RATE_LIMIT') {
    const entry = memory.rateLimitedIPs.get(action.target);
    if (entry && entry.actionId === action.actionId) {
      memory.rateLimitedIPs.delete(action.target);
    }
  }
  if (action.action === 'BLOCK_IP') {
    const entry = memory.blockedIPs.get(action.target);
    if (entry && entry.actionId === action.actionId) {
      memory.blockedIPs.delete(action.target);
    }
  }
}

function markRolledBack(memory, found, action, reason) {
  const updatedResponses = [...found.incident.responses];
  updatedResponses[found.index] = {
    ...action,
    status: 'ROLLED_BACK',
    rolledBackAt: now(),
    rollbackReason: reason
  };
  if (found.active) {
    memory.updateIncident(found.incident.id, { responses: updatedResponses });
  } else {
    found.incident.responses = updatedResponses;
  }
}

/** Sends a dashboard alert and records the notification in SharedMemory.
 * @param {{ message: string, severity: string, incidentId: string }} args - Alert arguments.
 * @param {object} context - Tool context.
 * @returns {{ actionTaken: string, actionId: string, rollbackToken: string | null, success: boolean, reasoning: string, blastRadius: string, duplicate: boolean, confidence: number }} Execution result.
 * @throws {Error} If arguments are invalid or the incident is missing. */
function execute_alert_only(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const agentName = context.agentName || 'ResponseExecutorTool';
    const incidentId = assertString(args.incidentId, 'incidentId');
    const message = assertString(args.message, 'message');
    const severity = assertString(args.severity, 'severity').toUpperCase();
    const actionId = lazyGenerateId();
    const reasoning = `Alert created for ${severity} incident ${incidentId}: ${message}`;

    preLog(memory, agentName, 'ALERT_ONLY', { incidentId, message, severity });
    const alert = { alertId: actionId, incidentId, message, severity, createdAt: now(), source: agentName };
    storeAlert(memory, alert);
    const record = responseRecord(actionId, 'ALERT_ONLY', incidentId, null, false, reasoning, agentName);
    const update = updateIncidentResponses(memory, incidentId, record);
    postLog(memory, agentName, 'ALERT_ONLY', { incidentId, actionId: update.record.actionId, duplicate: update.duplicate });
    emit(context, EVENTS.RESPONSE_EXECUTED, incidentId, { action: 'ALERT_ONLY', actionId: update.record.actionId, alert, duplicate: update.duplicate, confidence: 1 }, reasoning);

    return {
      actionTaken: 'ALERT_ONLY',
      actionId: update.record.actionId,
      rollbackToken: null,
      success: true,
      reasoning,
      blastRadius: 'No infrastructure or user traffic impact; dashboard notification only.',
      duplicate: update.duplicate,
      confidence: 1
    };
  } catch (error) {
    throw new Error(`execute_alert_only failed: ${error.message}`);
  }
}

/** Applies a reversible simulated rate limit to an IP address.
 * @param {{ ip: string, requestsPerMinute: number, durationMinutes?: number, reason: string, incidentId: string }} args - Rate-limit arguments.
 * @param {object} context - Tool context.
 * @returns {{ actionTaken: string, actionId: string, rollbackToken: string, success: boolean, reasoning: string, blastRadius: string, duplicate: boolean, confidence: number }} Execution result.
 * @throws {Error} If arguments are invalid or the incident is missing. */
function execute_rate_limit(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const agentName = context.agentName || 'ResponseExecutorTool';
    const ip = assertIp(args.ip);
    const incidentId = assertString(args.incidentId, 'incidentId');
    const reason = assertString(args.reason, 'reason');
    const requestsPerMinute = assertPositiveNumber(args.requestsPerMinute, 'requestsPerMinute');
    const durationMinutes = assertPositiveNumber(args.durationMinutes, 'durationMinutes', 60);
    const actionId = lazyGenerateId();
    const rollbackToken = lazyGenerateId();
    const expiresAt = new Date(Date.now() + durationMinutes * 60000).toISOString();
    const reasoning = `Applied simulated rate limit of ${requestsPerMinute} rpm to ${ip} for ${durationMinutes} minutes: ${reason}`;

    preLog(memory, agentName, 'RATE_LIMIT', { incidentId, ip, requestsPerMinute, durationMinutes, reason });
    const record = responseRecord(actionId, 'RATE_LIMIT', ip, rollbackToken, true, reasoning, agentName);
    const update = updateIncidentResponses(memory, incidentId, record);
    if (!update.duplicate) {
      memory.rateLimitedIPs.set(ip, { rateLimitedAt: now(), requestsPerMinute, reason, actionId, expiresAt, rollbackToken, incidentId });
    }
    postLog(memory, agentName, 'RATE_LIMIT', { incidentId, ip, actionId: update.record.actionId, expiresAt, duplicate: update.duplicate });
    emit(context, EVENTS.RESPONSE_EXECUTED, incidentId, { action: 'RATE_LIMIT', ip, actionId: update.record.actionId, expiresAt, duplicate: update.duplicate, confidence: 1 }, reasoning);

    return { actionTaken: 'RATE_LIMIT', actionId: update.record.actionId, rollbackToken: update.record.rollbackToken, success: true, reasoning, blastRadius: 'Only the suspicious source IP is throttled; legitimate hosts are unaffected.', duplicate: update.duplicate, confidence: 1 };
  } catch (error) {
    throw new Error(`execute_rate_limit failed: ${error.message}`);
  }
}

/** Applies a reversible simulated firewall block to an IP address.
 * @param {{ ip: string, durationHours?: number, reason: string, incidentId: string }} args - Block arguments.
 * @param {object} context - Tool context.
 * @returns {{ actionTaken: string, actionId: string, rollbackToken: string, success: boolean, reasoning: string, blastRadius: string, duplicate: boolean, confidence: number }} Execution result.
 * @throws {Error} If arguments are invalid or the incident is missing. */
function execute_block_ip(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const agentName = context.agentName || 'ResponseExecutorTool';
    const ip = assertIp(args.ip);
    const incidentId = assertString(args.incidentId, 'incidentId');
    const reason = assertString(args.reason, 'reason');
    const durationHours = assertPositiveNumber(args.durationHours, 'durationHours', 24);
    const actionId = lazyGenerateId();
    const rollbackToken = lazyGenerateId();
    const expiresAt = new Date(Date.now() + durationHours * 3600000).toISOString();
    const reasoning = `Applied simulated perimeter firewall block to ${ip} for ${durationHours} hour(s): ${reason}`;

    preLog(memory, agentName, 'BLOCK_IP', { incidentId, ip, durationHours, reason });
    const record = responseRecord(actionId, 'BLOCK_IP', ip, rollbackToken, true, reasoning, agentName);
    const update = updateIncidentResponses(memory, incidentId, record);
    if (!update.duplicate) {
      memory.blockedIPs.set(ip, { blockedAt: now(), reason, actionId, expiresAt, rollbackToken, incidentId });
      memory.systemStats.totalBlockedToday += 1;
    }
    postLog(memory, agentName, 'BLOCK_IP', { incidentId, ip, actionId: update.record.actionId, expiresAt, duplicate: update.duplicate });
    emit(context, EVENTS.RESPONSE_EXECUTED, incidentId, { action: 'BLOCK_IP', ip, actionId: update.record.actionId, expiresAt, duplicate: update.duplicate, confidence: 1 }, reasoning);

    return { actionTaken: 'BLOCK_IP', actionId: update.record.actionId, rollbackToken: update.record.rollbackToken, success: true, reasoning, blastRadius: 'Only traffic from the blocked source IP is denied at the simulated perimeter.', duplicate: update.duplicate, confidence: 1 };
  } catch (error) {
    throw new Error(`execute_block_ip failed: ${error.message}`);
  }
}

/** Reverses a previously executed response action using its rollback token.
 * @param {{ actionId: string, rollbackToken: string, reason: string }} args - Rollback arguments.
 * @param {object} context - Tool context.
 * @returns {{ actionTaken: string, actionId: string, success: boolean, reasoning: string, blastRadius: string, confidence: number }} Rollback result.
 * @throws {Error} If the action is missing, irreversible, token mismatches, or rollback fails. */
function rollback_action(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const agentName = context.agentName || 'ResponseExecutorTool';
    const actionId = assertString(args.actionId, 'actionId');
    const rollbackToken = assertString(args.rollbackToken, 'rollbackToken');
    const reason = assertString(args.reason, 'reason');
    const found = findAction(memory, actionId);
    if (!found) {
      throw new Error(`Response action not found: ${actionId}`);
    }
    const action = found.incident.responses[found.index];
    if (!action.rollbackAvailable) {
      throw new Error(`Response action ${actionId} does not support rollback.`);
    }
    if (action.rollbackToken !== rollbackToken) {
      throw new Error(`Rollback token mismatch for action ${actionId}.`);
    }

    preLog(memory, agentName, 'ROLLBACK', { incidentId: found.incident.id, actionId, reason });
    rollbackState(memory, action);
    markRolledBack(memory, found, action, reason);
    postLog(memory, agentName, 'ROLLBACK', { incidentId: found.incident.id, actionId, action: action.action });
    emit(context, EVENTS.RESPONSE_ROLLED_BACK, found.incident.id, { actionId, action: action.action, target: action.target, confidence: 1 }, `Rolled back ${action.action} on ${action.target}: ${reason}`);

    return { actionTaken: 'ROLLBACK', actionId, success: true, reasoning: `Rolled back ${action.action} on ${action.target}: ${reason}`, blastRadius: 'Original simulated enforcement state removed; no remaining system impact from this action.', confidence: 1 };
  } catch (error) {
    throw new Error(`rollback_action failed: ${error.message}`);
  }
}

module.exports = {
  execute_alert_only,
  execute_rate_limit,
  execute_block_ip,
  rollback_action
};
