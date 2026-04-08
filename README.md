# Governance Equipment

Fleet governance, audit trails, and policy enforcement for autonomous vessels.

## How It Works
- **Audit log**: Every fleet action recorded with actor, type, target, hash, autonomy level
- **Policy evaluation**: Actions checked against policies before execution
- **Autonomy-aware**: Policies apply only to specific autonomy levels (L0-L5)
- **Rate limiting**: 60 deploy actions per vessel per hour
- **Fail escalation**: 3+ failures on same target auto-escalates to human
- **Compliance scoring**: Per-vessel and fleet-wide compliance metrics

## Default Policies
| Policy | What It Does | Levels |
|--------|-------------|--------|
| Test Before Deploy | Deployments require approval at L3+ | L3-L5 |
| Delete Protection | Deletions require approval at L4+ | L4-L5 |
| Escalation Threshold | 3+ failures → human review | All |
| Rate Limit | Max 60 deploys/hour/vessel | All |

## Integration
```typescript
import { GovernanceEngine } from "./governance-equipment";

const gov = new GovernanceEngine();
const result = gov.evaluate({ actor: "studylog-ai", type: "deploy", target: "src/worker.ts", description: "Fix CSP", autonomyLevel: 3 });
// { allowed: false, requiresApproval: true, reason: "Deployments at high autonomy require human approval" }

gov.record({ actor: "casey", type: "approve", target: "studylog-ai", description: "Approved CSP fix", autonomyLevel: 5, approvedBy: "casey" });
```

## Persistence
Export/import audit log + policies as JSON for KV storage. Zero dependencies.

Superinstance & Lucineer (DiGennaro et al.)
