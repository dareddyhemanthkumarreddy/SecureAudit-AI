\### 2026-08-05

\- Set up full project scaffold (folders, venv, git, GitHub repo).

\- Built and tested Phase 1: FilePartitionManager (partition/partition.py) - splits files into 4096-byte blocks / 512-byte sub-blocks.

\- Built and tested Phase 1: CloudStorage simulator (storage/cloud\_storage.py) - saves partitioned data as base64-encoded JSON, standing in for a real cloud upload.

\- Wired both into main.py - runs end-to-end on sample.pdf (6.3MB -> 1548 blocks -> 12384 sub-blocks).

\- Verified numbers exactly match professor's original project at this stage, as expected (this stage isn't where our contribution lives).



\### 2026-08-05 (continued)

\- Installed cryptography library, added to requirements.txt.

\- Built KeyManager (signature/key\_manager.py) - generates RSA-2048 keypair, private key excluded from git via .gitignore.

\- Built SubsetSignature (signature/subset\_signature.py) - groups sub-blocks into subsets of 16, computes combined SHA-256 hash per subset, signs with RSA-PSS.

\- Tested on sample.pdf: 12384 sub-blocks -> 774 signed subsets in \~0.5 seconds.

\- Verified correctness: untampered subset passes verification, tampered subset (single byte changed) correctly fails.

\- This is our first real contribution beyond the professor's original project - he had no cryptographic signature layer at all.



\### 2026-08-05 (Phase 2 complete)

\- Built ChallengeGenerator (auditor/challenge.py) - TPA randomly selects 10% of signed subsets to challenge, reproducible via seed.

\- Built VerificationEngine (auditor/verification\_engine.py) - TPA verifies challenged subsets using ONLY the public key, no private key or trusted raw data needed.

\- Tested: 77/77 subsets pass when untampered. After deliberately tampering 1 subset, exactly 1 fails - precise detection confirmed, no false positives/negatives.

\- Wired full pipeline into main.py: partition -> sign -> upload -> challenge -> verify, all running end-to-end successfully.

\- Phase 2 complete. This is a real, working cryptographic integrity layer - a genuine improvement over the professor's original project, which had no signatures at all (signature field was always None).





\### 2026-08-05 (Phase 3 - simulators)

\- Built ModificationSimulator (simulation/modification\_simulator.py) - simulates legitimate, properly-tracked edits at configurable rate. Tested at 5%: 619/12384 sub-blocks modified correctly.

\- Built CorruptionSimulator (simulation/corruption\_simulator.py) - simulates silent corruption (data changes, no metadata trace). Tested at 2%: confirmed corrupted sub-blocks show completely normal metadata (version=1, modified=False, trust=100) - proves old-style metadata-only risk detection would miss this entirely.

\- Built AttackSimulator (simulation/attack\_simulator.py) - simulates adversary deliberately targeting the safest-looking (highest trust+stability) sub-blocks, to test if risk scoring can be gamed. Tested at 2% rate.

\- Key finding: signature verification (Phase 2) catches corruption/attacks that metadata-based risk scoring alone would miss - motivates combining both layers in final system.

\- All three simulators use MetadataTracker.apply\_modification() with track\_properly flag to control whether tracking happens - clean, reusable design.



\### 2026-08-05 (Phase 4 - feature extraction)

\- Installed pandas, numpy for structured data handling.

\- Built FeatureExtractor (features/feature\_extractor.py) - converts partitioned+simulated data into a clean (features -> true\_label) pandas DataFrame.

\- Features used: trust\_score, stability\_index, version, modified, challenge\_count, verification\_count.

\- Ran all 3 simulators together (5% modification, 2% corruption, 2% attack) on sample.pdf, extracted 12384 labeled rows: 1097 tampered (8.9%), 11287 untouched.

\- Saved dataset to results/raw/sample\_features.csv - this is our first real ML training dataset, ready for Phase 5.

\- Noted: verification\_count is currently always 0 in isolated tests since no TPA challenge ran in this test - will become meaningful once combined with Phase 2 in the full pipeline.





\###2026-08-07( Phase 5 - Risk Scorer, key finding)

\- Installed scikit-learn.

\- Built generate\_training\_data.py - runs 10 simulation rounds at varying rates, tags each row with tamper\_type (modification/corruption/attack/none). Generated 123,840 labeled rows: 9654 modification, 2536 corruption, 2098 attack, 109552 untouched.

\- Built RiskScorer (ai\_agent/risk\_scorer.py) - trains Random Forest and Gradient Boosting on trust\_score, stability\_index, version, modified, challenge\_count, verification\_count.

\- Overall metrics: AUC 0.8415, precision 1.0, recall 0.683 (both models identical).

\- IMPORTANT FINDING: broke down recall by tamper\_type - modification 100% detected, corruption 0% detected, attack 0% detected.

\- Root cause: corruption/attack simulators use track\_properly=False, so tampered sub-blocks have IDENTICAL metadata to untouched ones - no signal exists for ML to learn from.

\- This is NOT a bug - it's proof that metadata-based AI risk scoring structurally cannot catch untracked tampering, which is exactly why the system needs the cryptographic subset-signature layer (Phase 2) as a second, independent detection mechanism.

\- This becomes a core two-layer-defense argument for the paper: AI handles efficient detection of expected/tracked changes, signatures catch untracked/adversarial changes that AI cannot see by design.

\- verification\_count feature importance = 0.0000 - makes sense, no TPA challenge occurred in these isolated training runs. Will investigate combining with Phase 2 challenge data in a later experiment.



\### Phase 5 - Model refinement

\- Removed verification\_count feature (always 0 in current data, no signal, wasted capacity).

\- Tuned RF/GB hyperparameters, added 5-fold cross-validation for robustness check.

\- CV confirms model is stable: cv\_auc\_mean=0.8378, cv\_auc\_std=0.0239, closely matches single-split auc=0.8415.

\- RF and GB still produce identical results - confirmed this is because "modified" flag alone nearly perfectly separates the classes (only modification-type tampering sets it True). Not a bug - reflects genuine structure of current feature set.

\- Decision: keep Module 1 scoped to what it's honestly good at (tracked modifications, 100% recall), rely on Phase 2 signatures for untracked corruption/attacks. Revisit combining signature-verification results as a feature later if time allows.



\### Phase 5 - Threshold sweep finding

\- Ran threshold sweep (0.50-0.95): results completely flat across all thresholds.

\- Diagnosed: model outputs only 2 distinct probability values across 123,840 rows - 1.00 for modification (9654 rows), and an identical 0.2461 for corruption, attack, AND untouched rows combined (114,186 rows) - all indistinguishable to the model.

\- Root cause: corruption/attack/untouched share identical metadata (confirmed in earlier finding), so current Module 1 is functionally a binary classifier (modified flag), not yet a genuinely graded risk score.

\- Conclusion: threshold tuning is not meaningful until Module 1 has a feature that varies for corruption/attack/untouched cases specifically. Confirms need to integrate signature-verification result as a feature (deferred earlier) - this is the natural next improvement, not optional polish.

\- Current honest scope of Module 1: perfect binary detector for tracked modifications only. Documented as-is for now; will revisit with signature-derived features in a later phase.



\### Phase 6 - Anomaly Detector (Module 3) complete

\- Built generate\_session\_data.py - simulates 50 audit sessions (45 normal, 5 deliberately anomalous with high tampering rates 25-45% vs normal 1-8%), extracts 5 observable aggregate features per session (avg\_trust\_score, avg\_stability\_index, fraction\_modified, avg\_challenge\_count, pct\_low\_trust).

\- Built AnomalyDetector (ai\_agent/anomaly\_detector.py) using Isolation Forest, trained UNSUPERVISED (never sees true\_anomaly during training).

\- Result: 5/5 anomalous sessions correctly detected, 0 false positives, 0 false negatives. Clean score separation between normal and anomalous clusters.

\- This is a genuinely strong result - Module 3 successfully catches cross-session behavioral anomalies that Module 1 (per-block) isn't designed to see, validating the multi-module AI agent architecture.

\- Caveat to remember: only 50 sessions total, all from the same sample.pdf file with synthetically controlled rate ranges - real validation would need more files, more realistic anomaly scenarios, and testing at the boundary between normal/anomalous rates (not just clearly separated ranges).



\### Phase 7 - Audit Scheduler (Module 2) complete

\- Added scheduler config settings: base interval 24hrs, min 1hr, max 72hrs, risk\_weight=3.0, anomaly\_weight=5.0.

\- Built AuditScheduler (ai\_agent/audit\_scheduler.py) - computes adaptive next-audit interval using formula: interval = base / (1 + risk\*risk\_weight + anomaly\_penalty), bounded to \[min, max].

\- Tested using Module 3's actual anomaly predictions + fraction\_modified as risk proxy, across all 50 sessions.

\- Result: normal sessions average \~21 hours between audits, anomalous sessions drop to \~3.4 hours (\~7x more frequent) vs fixed 24-hour baseline.

\- This demonstrates the three modules working together as an integrated system: Module 1/aggregate risk + Module 3 anomaly flag -> Module 2 scheduling decision. Good evidence for paper's "unified AI agent" narrative.

\- Module 2 currently uses a simple adaptive formula, not full reinforcement learning (deferred as originally planned - can revisit as a stretch goal later).





\### Phase 8 - Garlic Bundling (Module 4) complete

\- Built GarlicBundler (garlic/garlic\_bundler.py) - mixes real audit requests with random decoys drawn from the full subset universe, shuffled before sending to TPA.

\- Built adversary simulation to test privacy: naive adversary tries to guess which bundle entries are real, averaged over 2000 trials (single-trial results were too noisy/unreliable - fixed this).

\- Result: adversary\_advantage \~0.00 across all decoy ratios (1, 2, 4, 8 decoys per real) - confirms bundle structure leaks no exploitable information, real requests are statistically indistinguishable from decoys.

\- Trade-off identified: more decoys = stronger privacy margin but more TPA verification overhead - this becomes a privacy-vs-efficiency graph for the paper.

\- Important note: "garlic bundling" is our own adapted design (inspired by anonymity network concepts), not a term with established grounding in cloud-auditing/PDP literature - must frame carefully in the paper as our design choice, verify with literature search before submission.



\### Phase 9 - Machine Unlearning complete

\- Updated generate\_session\_data.py to tag each session with user\_id (users 1-9 = normal, user 10 = the simulated compromised user, all 5 anomalous sessions belong to user 10).

\- Built MachineUnlearning (ai\_agent/unlearning.py) - implements EXACT unlearning via full retraining (not approximate) - mathematically identical to a model that never saw the removed user's data.

\- Tested: "forget user 10" - removed 5 sessions, retrained on remaining 45 from 9 users. Structural check passed (user 10 has zero rows in new training data).

\- Interesting diagnostic finding: after unlearning, all 5 of user 10's session scores become IDENTICAL (-0.597449) when evaluated by the new model - since they're now out-of-sample points evaluated against a boundary that never included them, rather than points that helped shape that boundary. All 5 scores shifted positively (less anomalous-looking) - consistent with removing an anomalous cluster from training data.

\- This is a clean, defensible unlearning result: structural removal is provable, and the behavioral difference (identical, shifted scores) makes intuitive sense given how Isolation Forest works.



\### Phase 10 - Baselines complete, key comparison result

\- Built 4 baseline strategies at subset-level: VerifyAll, RandomVerification (10%), MetadataVerification, RuleBasedAMTRS (professor's original rule logic, reimplemented).

\- Built baseline\_comparison.py - runs all baselines + our AI (Module 1) against realistic mixed tampering (5% mod, 2% corruption, 2% attack) on sample.pdf, 774 subsets, 525 truly tampered.

\- RESULTS: Verify-All 100% recall/0% efficiency. Random 14.7% recall/90% efficiency (confirms random sampling is a genuinely weak baseline). Metadata-Only, Rule-Based AMTRS, and Our AI (Module 1) are ALL IDENTICAL: 80.8% recall, 45.2% efficiency.

\- This confirms (again, now at subset level) that ALL metadata-driven approaches - baseline or AI-powered - hit the same structural ceiling, since corruption/attack tampering leaves no metadata trace for any of them to detect.

\- Strengthens paper's core argument: no single layer (metadata-based selection OR signatures alone) is sufficient. The combination (efficient AI-driven screening + cryptographic signature verification for what screening misses) is the actual contribution, not either piece alone.

\- Saved comparison table to results/processed/baseline\_comparison.csv - ready for paper's main results table.





\### Phase 11 - Full Pipeline Sweep complete (capstone experiment)

\- Corrected earlier flawed idea: feeding signature verification results INTO Module 1 as a feature is circular (can't use the answer to decide whether to check). Real fix: layer a random "safety net" (10% of Module-1-LOW subsets) that still gets real cryptographic verification, catching corruption/attack tampering Module 1 structurally misses.

\- Built full\_pipeline\_sweep.py - runs Verify-All, Random, Metadata-Only, Rule-Based AMTRS, and Our Full System (AI + safety net) across 4 modification rates (1%, 5%, 10%, 20%) x 5 runs each = 20 full pipeline rounds, using REAL signature verification (not ground-truth cheating) to measure recall.

\- KEY FINDING: Our Full System shows a real, consistent recall improvement over Metadata-Only/Rule-Based AMTRS at every rate, but the improvement SHRINKS as modification rate increases: +7 points at 1% rate (36.9% -> 44.0%), down to negligible at 20% rate (99.3% -> 99.3%).

\- Explanation: at low modification rates, most true tampering is corruption/attack-type (invisible to metadata) - safety net has real work to do. At high rates, legitimate modifications dominate and metadata-only methods already perform well, so safety net adds less value.

\- Genuine trade-off identified: safety net costs efficiency too (e.g. at 1% rate: 76.8% vs 85.3% work saved) for its recall gain - not a free win, a real trade-off to present honestly.

\- This becomes a strong, nuanced paper narrative: our hybrid approach helps most exactly where metadata-only methods are weakest, rather than claiming uniform superiority everywhere.

\- Saved raw sweep data (results/raw/full\_pipeline\_sweep.csv) and averaged summary (results/processed/full\_pipeline\_summary.csv) - ready for Phase 12 graphs.

