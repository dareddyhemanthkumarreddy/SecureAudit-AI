\### 2026-08-05

\- Set up full project scaffold (folders, venv, git, GitHub repo).

\- Built and tested Phase 1: FilePartitionManager (partition/partition.py) - splits files into 4096-byte blocks / 512-byte sub-blocks.

\- Built and tested Phase 1: CloudStorage simulator (storage/cloud\_storage.py) - saves partitioned data as base64-encoded JSON, standing in for a real cloud upload.

\- Wired both into main.py - runs end-to-end on sample.pdf (6.3MB -> 1548 blocks -> 12384 sub-blocks).

\- Verified numbers exactly match professor's original project at this stage, as expected (this stage isn't where our contribution lives).

