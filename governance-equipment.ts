// governance-equipment.ts — Fleet governance, audit trails, and policy enforcement
// Synthesized from nexus trust engine + EU AI Act compliance + Cocapn fleet protocol
// Zero deps, ~200 lines

export interface GovernanceAction {
  id: string;
  actor: string;       // vessel or human
  type: "create" | "modify" | "delete" | "deploy" | "revert" | "escalate" | "approve";
  target: string;      // repo, vessel, or resource
  description: string;
  timestamp: string;
  hash: string;        // content hash for integrity
  approvedBy?: string;
  autonomyLevel: number; // 0-5, what level the vessel was at
}

export interface GovernancePolicy {
  id: string;
  name: string;
  description: string;
  rules: PolicyRule[];
  applicableLevels: number[]; // which autonomy levels this applies to
  enabled: boolean;
}

export interface PolicyRule {
  field: string;
  operator: "eq" | "neq" | "gt" | "lt" | "gte" | "lte" | "contains" | "regex";
  value: string | number;
  action: "allow" | "deny" | "escalate" | "require_approval";
  reason: string;
}

export interface AuditQuery {
  actor?: string;
  type?: string;
  target?: string;
  since?: string;
  until?: string;
  limit?: number;
}

// Default fleet policies
const DEFAULT_POLICIES: GovernancePolicy[] = [
  {
    id: "no-deploy-without-test",
    name: "Test Before Deploy",
    description: "Vessels must pass health checks before deployment is approved",
    applicableLevels: [3, 4, 5],
    enabled: true,
    rules: [
      { field: "type", operator: "eq", value: "deploy", action: "require_approval", reason: "Deployments at high autonomy require human approval" },
    ],
  },
  {
    id: "delete-protection",
    name: "Delete Protection",
    description: "Deletions at high autonomy require approval",
    applicableLevels: [4, 5],
    enabled: true,
    rules: [
      { field: "type", operator: "eq", value: "delete", action: "require_approval", reason: "Deletes at high autonomy require human approval" },
    ],
  },
  {
    id: "escalation-required",
    name: "Escalation Threshold",
    description: "If a vessel fails 3+ times on same target, escalate to human",
    applicableLevels: [0, 1, 2, 3, 4, 5],
    enabled: true,
    rules: [
      { field: "failCount", operator: "gte", value: 3, action: "escalate", reason: "3+ failures on same target requires human review" },
    ],
  },
  {
    id: "rate-limit",
    name: "Action Rate Limit",
    description: "Max 60 deploy actions per hour per vessel",
    applicableLevels: [0, 1, 2, 3, 4, 5],
    enabled: true,
    rules: [
      { field: "type", operator: "eq", value: "deploy", action: "deny", reason: "Rate limit exceeded (60/hour)" },
    ],
  },
];

export class GovernanceEngine {
  private auditLog: GovernanceAction[] = [];
  private policies: Map<string, GovernancePolicy> = new Map();
  private failCounts: Map<string, number> = new Map(); // target → count
  private rateLimits: Map<string, { count: number; windowStart: number }> = new Map();
  private counter = 0;
  private readonly RATE_LIMIT_WINDOW = 3600000; // 1 hour
  private readonly RATE_LIMIT_MAX = 60;

  constructor() {
    for (const policy of DEFAULT_POLICIES) {
      this.policies.set(policy.id, policy);
    }
  }

  private nextId(): string {
    return `gov_${Date.now()}_${++this.counter}`;
  }

  // Simple hash for integrity (not crypto-grade)
  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit int
    }
    return Math.abs(hash).toString(36);
  }

  // Record an action in the audit log
  record(action: Omit<GovernanceAction, "id" | "timestamp" | "hash">): GovernanceAction {
    const full: GovernanceAction = {
      ...action,
      id: this.nextId(),
      timestamp: new Date().toISOString(),
      hash: this.simpleHash(action.description + action.target + action.type),
    };
    this.auditLog.push(full);

    // Track fail counts
    if (action.type === "escalate") {
      const current = this.failCounts.get(action.target) || 0;
      this.failCounts.set(action.target, current + 1);
    }

    return full;
  }

  // Check if an action is allowed under current policies
  evaluate(action: Omit<GovernanceAction, "id" | "timestamp" | "hash">): {
    allowed: boolean;
    requiresApproval: boolean;
    reason: string;
    matchedPolicy?: string;
  } {
    const applicablePolicies = Array.from(this.policies.values()).filter(
      p => p.enabled && p.applicableLevels.includes(action.autonomyLevel)
    );

    for (const policy of applicablePolicies) {
      for (const rule of policy.rules) {
        const fieldValue = this.getFieldValue(action, rule.field);
        
        let matches = false;
        switch (rule.operator) {
          case "eq": matches = fieldValue === rule.value; break;
          case "neq": matches = fieldValue !== rule.value; break;
          case "gt": matches = Number(fieldValue) > Number(rule.value); break;
          case "lt": matches = Number(fieldValue) < Number(rule.value); break;
          case "gte": matches = Number(fieldValue) >= Number(rule.value); break;
          case "lte": matches = Number(fieldValue) <= Number(rule.value); break;
          case "contains": matches = String(fieldValue).includes(String(rule.value)); break;
        }

        if (matches) {
          if (rule.action === "deny") {
            return { allowed: false, requiresApproval: false, reason: rule.reason, matchedPolicy: policy.id };
          }
          if (rule.action === "require_approval") {
            return { allowed: false, requiresApproval: true, reason: rule.reason, matchedPolicy: policy.id };
          }
          if (rule.action === "escalate") {
            return { allowed: true, requiresApproval: false, reason: rule.reason, matchedPolicy: policy.id };
          }
        }
      }
    }

    // Check rate limit for deploy actions
    if (action.type === "deploy") {
      const rateKey = action.actor;
      const rate = this.rateLimits.get(rateKey);
      const now = Date.now();
      
      if (rate && now - rate.windowStart < this.RATE_LIMIT_WINDOW) {
        if (rate.count >= this.RATE_LIMIT_MAX) {
          return { allowed: false, requiresApproval: false, reason: "Rate limit exceeded (60 deploys/hour)", matchedPolicy: "rate-limit" };
        }
        rate.count++;
      } else {
        this.rateLimits.set(rateKey, { count: 1, windowStart: now });
      }
    }

    return { allowed: true, requiresApproval: false, reason: "" };
  }

  private getFieldValue(action: any, field: string): any {
    if (field in action) return action[field];
    if (field === "failCount") return this.failCounts.get(action.target) || 0;
    return undefined;
  }

  // Query audit log
  query(q: AuditQuery): GovernanceAction[] {
    let results = [...this.auditLog];
    
    if (q.actor) results = results.filter(a => a.actor === q.actor);
    if (q.type) results = results.filter(a => a.type === q.type);
    if (q.target) results = results.filter(a => a.target === q.target);
    if (q.since) results = results.filter(a => a.timestamp >= q.since);
    if (q.until) results = results.filter(a => a.timestamp <= q.until);
    if (q.limit) results = results.slice(-q.limit);
    
    return results;
  }

  // Add custom policy
  addPolicy(policy: GovernancePolicy): void {
    this.policies.set(policy.id, policy);
  }

  // Get compliance score for a vessel
  complianceScore(vessel: string): { score: number; violations: number; total: number } {
    const actions = this.query({ actor: vessel });
    const violations = actions.filter(a => a.type === "escalate").length;
    const total = actions.length;
    const score = total === 0 ? 100 : Math.round(((total - violations) / total) * 100);
    return { score, violations, total };
  }

  // Fleet-wide governance summary
  fleetSummary(): { totalActions: number; vessels: number; policies: number; avgCompliance: number } {
    const vessels = new Set(this.auditLog.map(a => a.actor));
    let totalCompliance = 0;
    let vesselCount = 0;
    
    for (const v of vessels) {
      totalCompliance += this.complianceScore(v).score;
      vesselCount++;
    }
    
    return {
      totalActions: this.auditLog.length,
      vessels: vesselCount,
      policies: this.policies.size,
      avgCompliance: vesselCount === 0 ? 100 : Math.round(totalCompliance / vesselCount),
    };
  }

  // Export/import for KV persistence
  exportState(): string {
    return JSON.stringify({
      auditLog: this.auditLog,
      policies: Object.fromEntries(this.policies),
      failCounts: Object.fromEntries(this.failCounts),
    });
  }

  importState(json: string): void {
    const data = JSON.parse(json);
    if (data.auditLog) this.auditLog = data.auditLog;
    if (data.policies) {
      for (const [k, v] of Object.entries(data.policies)) {
        this.policies.set(k, v as GovernancePolicy);
      }
    }
    if (data.failCounts) {
      for (const [k, v] of Object.entries(data.failCounts)) {
        this.failCounts.set(k, v as number);
      }
    }
  }
}
