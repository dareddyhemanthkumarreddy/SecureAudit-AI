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



