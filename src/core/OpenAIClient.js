const OpenAI = require('openai');
const config = require('../config/env');
const { withRetry } = require('../utils/retry');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');

const logger = createLogger('OpenAIClient');

const MOCK_RESPONSES = Object.freeze({
  analyze_log_batch: {
    detectedEvents: [{
      type: 'BRUTE_FORCE',
      sourceIP: '203.0.113.45',
      targetService: 'ssh',
      confidence: 0.87,
      evidence: ['150 failed auth attempts followed by one successful login'],
      suggestedMitreTechnique: 'T1110'
    }],
    overallAssessment: 'Active brute force attack detected against SSH with successful credential compromise.',
    recommendsEscalation: true,
    confidence: 0.87
  },
  lookup_threat_feed: {
    feedMatches: [{ indicator: '203.0.113.45', source: 'AlienVault OTX', title: 'Known C2 Server', severity: 'HIGH' }],
    cveIds: [],
    threatActorProfile: 'Opportunistic scanner using automated credential attacks',
    recommendations: ['Block the source IP', 'Review the compromised backup account'],
    updatedConfidence: 0.91,
    confidence: 0.91
  },
  calculate_risk_score: {
    riskScore: 7,
    severity: 'HIGH',
    confidence: 0.87,
    reasoning: 'Active brute force from known bad IP against SSH service with likely account compromise.'
  },
  determine_response_level: {
    responseLevel: 3,
    requiresHITL: false,
    confidence: 0.87,
    reasoning: 'Risk score 7 and confidence above 0.75 make automated IP blocking appropriate.'
  },
  execute_alert_only: {
    actionTaken: 'ALERT_ONLY',
    actionId: 'mock-alert-action',
    rollbackToken: null,
    success: true,
    reasoning: 'Analyst notification was emitted without system state changes.',
    blastRadius: 'No operational impact.',
    confidence: 1
  },
  execute_block_ip: {
    success: true,
    actionId: 'mock-action-uuid',
    rollbackToken: 'mock-rollback-token',
    blastRadius: 'Single IP blocked, no collateral impact',
    reasoning: 'Mock perimeter firewall state was updated for the suspicious source IP.',
    confidence: 1
  },
  collect_evidence: {
    evidenceBundle: ['150 failed auth log lines collected', '1 successful auth log line collected'],
    confidence: 0.86
  },
  simulate_attack_scenario: {
    scenario: 'BRUTE_FORCE',
    steps: ['Reconnaissance: port scan', 'Credential attack: SSH brute force', 'Initial access: weak password'],
    logArtifacts: ['Jun 20 10:23:01 webserver sshd: Failed password for root from 203.0.113.45 port 52301 ssh2'],
    confidence: 0.9
  },
  deploy_honeypot: {
    honeypotId: 'mock-honeypot-uuid',
    assetType: 'FAKE_SSH_SERVER',
    status: 'DEPLOYED',
    confidence: 0.95
  }
});

function resolveOpenAIConstructor() {
  return OpenAI && OpenAI.default ? OpenAI.default : OpenAI;
}

function firstToolName(tools) {
  if (!Array.isArray(tools) || tools.length === 0 || !tools[0].function) {
    return 'default';
  }
  return tools[0].function.name || 'default';
}

function promptText(options) {
  return (options.messages || [])
    .map((message) => (typeof message.content === 'string' ? message.content : JSON.stringify(message.content || '')))
    .join('\n');
}

function selectMockToolName(options) {
  const names = Array.isArray(options.tools)
    ? options.tools.map((tool) => tool.function && tool.function.name).filter(Boolean)
    : [];
  const text = promptText(options);
  const requested = names.find((name) => text.includes(name));
  return requested || firstToolName(options.tools);
}

function textHas(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function approximateTokens(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value || '');
  return Math.max(1, Math.ceil(text.length / 4));
}

function buildScenarioAnalyzePayload(text) {
  if (textHas(text, [/vssadmin/i, /\.encrypted\b/i, /RANSOMWARE/i, /backup service termination/i])) {
    return {
      detectedEvents: [{
        type: 'RANSOMWARE',
        sourceIP: '10.0.0.42',
        targetHost: 'fileshare',
        targetService: 'endpoint',
        confidence: 0.94,
        evidence: ['vssadmin.exe delete shadows /all /quiet', 'mass .encrypted file rename events', 'SMB workstation-to-workstation lateral movement'],
        suggestedMitreTechnique: 'T1486',
        severity: 'CRITICAL'
      }],
      overallAssessment: 'Ransomware impact behavior and lateral movement detected across workstation and file-share logs.',
      recommendsEscalation: true,
      confidence: 0.94
    };
  }
  if (textHas(text, [/CANARY/i, /exfil-domain/i, /DATA_EXFILTRATION/i])) {
    return {
      detectedEvents: [{
        type: 'DATA_EXFILTRATION',
        sourceIP: '10.0.0.87',
        targetHost: 'fileserver',
        targetService: 'dns',
        confidence: 0.88,
        evidence: ['Repeated DNS queries to exfil-domain', 'CANARY file access from workstation'],
        suggestedMitreTechnique: 'T1048',
        severity: 'HIGH'
      }],
      overallAssessment: 'Possible slow DNS exfiltration with a canary file access signal.',
      recommendsEscalation: true,
      confidence: 0.88
    };
  }
  return MOCK_RESPONSES.analyze_log_batch;
}

function buildScenarioClassificationPayload(text) {
  if (textHas(text, [/RANSOMWARE/i, /vssadmin/i, /\.encrypted\b/i])) {
    return {
      type: 'RANSOMWARE',
      severity: 'CRITICAL',
      confidence: 0.94,
      suggestedMitreTechnique: 'T1486',
      mitreTactics: ['Impact', 'Lateral Movement'],
      reasoning: 'Shadow copy deletion, mass encryption, and lateral SMB/RDP activity indicate ransomware.'
    };
  }
  if (textHas(text, [/DATA_EXFILTRATION/i, /CANARY/i, /exfil-domain/i])) {
    return {
      type: 'DATA_EXFILTRATION',
      severity: 'HIGH',
      confidence: 0.88,
      suggestedMitreTechnique: 'T1048',
      mitreTactics: ['Exfiltration'],
      reasoning: 'Canary access and suspicious DNS patterns indicate possible exfiltration.'
    };
  }
  return {
    type: 'BRUTE_FORCE',
    severity: 'HIGH',
    confidence: 0.89,
    suggestedMitreTechnique: 'T1110',
    mitreTactics: ['Credential Access'],
    reasoning: 'Repeated failed SSH authentication followed by success indicates brute force.'
  };
}

function buildScenarioRiskPayload(text) {
  if (textHas(text, [/"threatSeverity":\s*"CRITICAL"/i, /RANSOMWARE/i, /"lateralMovementDetected":\s*true/i])) {
    return {
      riskScore: 9,
      severity: 'CRITICAL',
      confidence: 0.94,
      reasoning: 'Critical ransomware with lateral movement requires high-impact containment review.'
    };
  }
  if (textHas(text, [/DATA_EXFILTRATION/i, /"dataExfiltrationInProgress":\s*true/i])) {
    return {
      riskScore: 8,
      severity: 'CRITICAL',
      confidence: 0.88,
      reasoning: 'Potential exfiltration against sensitive files requires analyst-gated containment.'
    };
  }
  return MOCK_RESPONSES.calculate_risk_score;
}

function riskScoreFromText(text) {
  const match = text.match(/"riskScore":\s*(10|[1-9])/i) || text.match(/\briskScore\b[^0-9]*(10|[1-9])/i);
  return match ? Number(match[1]) : null;
}

function buildScenarioResponseLevelPayload(text) {
  const riskScore = riskScoreFromText(text);
  if (riskScore >= 10) {
    return {
      responseLevel: 5,
      requiresHITL: true,
      confidence: 0.95,
      reasoning: 'Risk 10 maps to shutdown and must wait for human approval.'
    };
  }
  if (riskScore >= 8 || textHas(text, [/RANSOMWARE/i, /DATA_EXFILTRATION/i])) {
    return {
      responseLevel: 4,
      requiresHITL: true,
      confidence: 0.92,
      reasoning: 'Risk 8-9 maps to machine isolation and must wait for human approval.'
    };
  }
  if (riskScore >= 6 || textHas(text, [/BRUTE_FORCE/i])) {
    return MOCK_RESPONSES.determine_response_level;
  }
  if (riskScore >= 4) {
    return {
      responseLevel: 2,
      requiresHITL: false,
      confidence: 0.75,
      reasoning: 'Risk 4-5 maps to reversible rate limiting.'
    };
  }
  return {
    responseLevel: 1,
    requiresHITL: false,
    confidence: 0.7,
    reasoning: 'Low risk maps to alert-only monitoring.'
  };
}

function buildMitrePayload(text) {
  if (textHas(text, [/RANSOMWARE/i, /T1486/i, /lateral/i])) {
    return {
      mitreTechniques: ['T1486', 'T1021', 'T1562'],
      mitreTactics: ['Impact', 'Lateral Movement', 'Defense Evasion'],
      confidence: 0.9,
      recommendations: ['Isolate affected workstation after HITL approval', 'Preserve endpoint and file-share evidence']
    };
  }
  if (textHas(text, [/DATA_EXFILTRATION/i, /exfil/i, /CANARY/i])) {
    return {
      mitreTechniques: ['T1048', 'T1567'],
      mitreTactics: ['Exfiltration'],
      confidence: 0.84,
      recommendations: ['Review DNS logs', 'Rotate exposed credentials and investigate canary access']
    };
  }
  return {
    mitreTechniques: ['T1110', 'T1078'],
    mitreTactics: ['Credential Access', 'Initial Access'],
    confidence: 0.86,
    recommendations: ['Block the source IP', 'Review successful login activity']
  };
}

function buildMockPayload(toolName, text) {
  if (toolName === 'analyze_log_batch') return buildScenarioAnalyzePayload(text);
  if (toolName === 'classify_attack_type') return buildScenarioClassificationPayload(text);
  if (toolName === 'calculate_risk_score') return buildScenarioRiskPayload(text);
  if (toolName === 'determine_response_level') return buildScenarioResponseLevelPayload(text);
  if (toolName === 'map_to_mitre_attack') return buildMitrePayload(text);
  return MOCK_RESPONSES[toolName] || {
    summary: 'Mock reasoning completed without a specialized tool response.',
    confidence: 0.72,
    reasoning: `No specialized mock response registered for ${toolName}.`
  };
}

function buildMockChatCompletion(options) {
  const toolName = selectMockToolName(options);
  const text = promptText(options);
  const payload = buildMockPayload(toolName, text);
  const content = JSON.stringify(payload);
  const promptTokens = approximateTokens(options.messages);
  const completionTokens = approximateTokens(content);
  return {
    id: `chatcmpl-mock-${generateId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: options.model || config.openaiModelPrimary,
    choices: [{
      index: 0,
      message: { role: 'assistant', content },
      finish_reason: 'stop'
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens
    }
  };
}

function buildMockEmbedding(text) {
  const source = String(text || '');
  const vector = [];
  for (let index = 0; index < 128; index += 1) {
    const charCode = source.charCodeAt(index % Math.max(source.length, 1)) || 0;
    vector.push(Number((((charCode + index) % 101) / 100).toFixed(4)));
  }
  return vector;
}

/**
 * Retry-aware OpenAI SDK wrapper with deterministic mock mode and cumulative token accounting.
 */
class OpenAIClient {
  /**
   * Creates an OpenAI client using validated application config.
   */
  constructor() {
    this.totalInputTokens = 0;
    this.totalOutputTokens = 0;
    this.totalTokens = 0;
    this.client = null;

    if (!config.mockMode) {
      const OpenAIConstructor = resolveOpenAIConstructor();
      this.client = new OpenAIConstructor({ apiKey: config.openAiApiKey });
    }
  }

  /**
   * Calls chat.completions.create with retry logic and token accounting.
   * @param {object} options - OpenAI chat completion options.
   * @returns {Promise<object>} Raw OpenAI chat completion response.
   * @throws {Error} If the request fails after retries or options are invalid.
   */
  async chatCompletion(options) {
    try {
      if (!options || !Array.isArray(options.messages)) {
        throw new Error('chatCompletion requires options.messages array.');
      }
      const requestOptions = { model: config.openaiModelPrimary, ...options };
      const response = config.mockMode
        ? buildMockChatCompletion(requestOptions)
        : await withRetry(
          () => this.client.chat.completions.create(requestOptions),
          {
            maxRetries: config.maxOpenAIRetries,
            baseDelayMs: config.openaiRetryBaseDelayMs,
            onRetry: (error, attemptNumber) => {
              logger.warn('Retrying OpenAI chat completion', { attemptNumber, error: error.message });
            }
          }
        );

      this.recordUsage(response.usage);
      return response;
    } catch (error) {
      logger.error('OpenAI chat completion failed', { error: error.message, stack: error.stack });
      throw new Error(`OpenAI chat completion failed: ${error.message}`);
    }
  }

  /**
   * Creates an embedding vector for text with retry logic.
   * @param {string} text - Text to embed.
   * @returns {Promise<number[]>} Embedding vector.
   * @throws {Error} If embedding generation fails.
   */
  async getEmbedding(text) {
    try {
      if (typeof text !== 'string' || text.length === 0) {
        throw new Error('getEmbedding requires non-empty text.');
      }
      if (config.mockMode) {
        return buildMockEmbedding(text);
      }
      const response = await withRetry(
        () => this.client.embeddings.create({ model: 'text-embedding-3-small', input: text }),
        {
          maxRetries: config.maxOpenAIRetries,
          baseDelayMs: config.openaiRetryBaseDelayMs,
          onRetry: (error, attemptNumber) => {
            logger.warn('Retrying OpenAI embedding request', { attemptNumber, error: error.message });
          }
        }
      );
      this.recordUsage(response.usage);
      return response.data[0].embedding;
    } catch (error) {
      logger.error('OpenAI embedding failed', { error: error.message, stack: error.stack });
      throw new Error(`OpenAI embedding failed: ${error.message}`);
    }
  }

  /**
   * Returns cumulative usage and estimated GPT-4o cost.
   * @returns {{ totalInputTokens: number, totalOutputTokens: number, totalTokens: number, estimatedCostUSD: number }} Usage stats.
   */
  getUsageStats() {
    const inputCost = (this.totalInputTokens / 1000000) * 5;
    const outputCost = (this.totalOutputTokens / 1000000) * 15;
    return {
      totalInputTokens: this.totalInputTokens,
      totalOutputTokens: this.totalOutputTokens,
      totalTokens: this.totalTokens,
      estimatedCostUSD: Number((inputCost + outputCost).toFixed(6))
    };
  }

  /**
   * Records token usage from an OpenAI response.
   * @param {object | undefined} usage - OpenAI usage object.
   * @returns {void}
   */
  recordUsage(usage) {
    const inputTokens = usage && usage.prompt_tokens ? usage.prompt_tokens : 0;
    const outputTokens = usage && usage.completion_tokens ? usage.completion_tokens : 0;
    const totalTokens = usage && usage.total_tokens ? usage.total_tokens : inputTokens + outputTokens;
    this.totalInputTokens += inputTokens;
    this.totalOutputTokens += outputTokens;
    this.totalTokens += totalTokens;
  }
}

module.exports = OpenAIClient;
