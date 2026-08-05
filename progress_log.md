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





