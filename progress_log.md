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

