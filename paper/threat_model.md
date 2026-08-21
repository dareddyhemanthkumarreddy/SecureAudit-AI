# SecureAudit-AI — Threat Model

## 1. System Entities

- **Data Owner** — holds the RSA private key, uploads files, and initiates audits. Trusted.
- **Cloud Server** — stores the partitioned, signed data. **Not fully trusted** — may be honest-but-careless (data corruption), or actively dishonest (attempts to hide missing/altered data).
- **Third-Party Auditor (TPA)** — receives challenge requests (via garlic bundles) and verifies subset signatures using only the public key. **Semi-trusted**: assumed to correctly execute the verification protocol, but not trusted to keep which subsets it audited confidential without the garlic bundling countermeasure.

## 2. Assets to Protect

1. **Data integrity** — the owner must be able to detect if stored data has been modified, corrupted, or deleted without authorization.
2. **Selection privacy** — the TPA should not be able to determine which specific subsets the owner's risk-assessment system considers suspicious.
3. **Data-subject privacy in the AI models** — a user's contribution to Module 3's training data must be provably removable on request.

## 3. Adversary Capabilities Considered

| Adversary | Capability Assumed | Goal |
|---|---|---|
| Dishonest cloud server | Can modify, delete, or corrupt any stored data; can attempt to fabricate responses to challenges | Hide data loss/corruption from the owner |
| Passive network observer / curious TPA | Can see every request in a garlic bundle | Determine which subsets the owner considers risky |
| Adaptive attacker with system knowledge | Knows the AI risk-scoring logic and deliberately targets data least likely to be flagged (modeled directly by our Attack Simulator, Phase 3) | Corrupt data while evading detection |
| External party requesting data erasure | A legitimate user invoking their right to be forgotten | N/A — this is a legitimate actor, not an adversary, but the system must respond correctly to this request (Phase 9) |

## 4. What the System DOES Defend Against (with evidence)

- **Undetected data tampering, in general** — any change to signed data is caught by RSA-PSS signature verification with cryptographic certainty (Phase 2 evidence: 76/77 pass, 1/77 fail on deliberately tampered data; zero false positives across all Phase 10/11/multi-file tests).
- **A dishonest server attempting to fabricate a valid-looking response** — computationally infeasible without the private key, by the standard unforgeability property of RSA signatures. We do not construct a formal cryptographic proof of this in this project; we rely on RSA's well-established security guarantees.
- **An adversary targeting the "safest-looking" data to evade a naive risk-based selection policy** — directly modeled by our Attack Simulator (Phase 3), and shown to still be caught at meaningful rates by the safety-net layer (Phase 11), though with lower recall than tracked modifications (see Section 5).
- **A TPA attempting to infer which subsets are genuinely of concern to the owner, from the bundle alone** — statistically shown to fail, with adversary advantage near zero (Phase 8).
- **Retained influence of a specific user's data in the trained anomaly model after a deletion request** — provably removed via exact retraining-based unlearning (Phase 9).

## 5. What the System Does NOT (Fully) Defend Against — Stated Honestly

- **Silent corruption or attack-type tampering on subsets that are never selected for verification.** Our system does not verify 100% of subsets on every audit (that would defeat the efficiency goal). Corruption/attack-type tampering on a subset that is neither flagged by Module 1 nor caught by the random safety net will go undetected until a future audit happens to select it. This is a probabilistic, not absolute, guarantee — consistent with the entire PDP/PoR field's approach (classical schemes also rely on probabilistic sampling, not exhaustive checking).
- **A cloud server that colludes with, or compromises, the TPA itself.** Our threat model assumes the TPA correctly executes the verification protocol even though it is not trusted with selection privacy. A fully malicious TPA that lies about verification results is outside our current scope.
- **Attacks on the RSA private key itself** (theft, side-channel extraction, weak key generation). We rely on standard key management practice (2048-bit RSA, generated via a well-audited library) but do not implement additional key-protection mechanisms (e.g., HSM integration) in this prototype.
- **Denial-of-service or availability attacks** against the cloud server or TPA (e.g., a server that is simply offline). Our system addresses integrity and selection privacy, not availability.
- **An adversary who can observe network traffic timing or volume patterns across many audits over time**, potentially correlating bundle sizes or challenge frequency with real risk levels even without seeing bundle contents. Our privacy validation (Phase 8) tests only a single-bundle, content-based adversary; a timing/traffic-analysis adversary is not modeled.
- **Full 100% detection guarantee at low tampering rates.** As shown empirically (Phase 11), our hybrid system's recall at low modification rates (e.g., 44% at 1%) is meaningfully below 100%, though better than pure metadata-only baselines (37%). This is an honest, quantified limitation, not a claimed guarantee.

## 6. Design Implication: This is a Probabilistic, Efficiency-Oriented Guarantee — Not an Absolute One

Consistent with the broader PDP/PoR field (Ateniese et al.'s original PDP scheme also relies on random sampling, not exhaustive verification), our system trades a small, quantified, and honestly reported probability of missed detection for substantial efficiency gains. The correct way to characterize our contribution is: **for a given verification budget, our hybrid AI-plus-cryptographic-safety-net approach achieves higher detection recall than comparable metadata-only selection strategies, particularly at low tampering rates** — not an unconditional "always detects everything" claim.
