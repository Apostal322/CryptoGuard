"""Cross-wallet address-poisoning campaign analysis (experimental, shadow mode only).

Four distinct concepts, never conflated:

- **attempt** (``attempts.py``): one observed planting event that meets the existing
  detector's evidence criteria for one victim wallet;
- **candidate relationship** (``relations.py``): two attempts share a specific, verifiable
  piece of planting-side infrastructure (a transaction, a signer, a lookalike, ...);
- **candidate campaign cluster** (``cluster.py``): attempts grouped by explicitly listed
  relationships, with every merging link shown;
- **common operator**: an attribution CryptoGuard never makes. A cluster says the attempts
  share infrastructure, not who controls it.
"""
