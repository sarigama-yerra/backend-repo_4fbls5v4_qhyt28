# Plinko Lab (Provably‑Fair)

Live URLs
- Frontend: (provided by preview)
- Backend: (provided by preview)

Overview
Plinko Lab is a deterministic, provably‑fair Plinko game featuring:
- Commit‑reveal with client contribution
- Deterministic engine + verifier
- MongoDB logging
- Responsive UI with Spline hero

Fairness Spec
- commitHex = SHA256(serverSeed:nonce)
- combinedSeed = SHA256(serverSeed:clientSeed:nonce)
- PRNG: xorshift32 seeded from first 4 bytes (big‑endian) of combinedSeed
- Peg map: rows R=12; for each row r (0..R-1) create r+1 pegs with leftBias = 0.5 + (rand() - 0.5)*0.2, rounded to 6 decimals. pegMapHash = SHA256(JSON.stringify(pegMap)).
- Path decisions: pos = count of Right; for row r use peg index min(pos, r). Adjust bias by dropColumn: adj = (dropColumn - floor(R/2)) * 0.01 then clamp. If rand() < bias' choose Left else Right.
- Bin index = pos.

API (key)
- POST /api/rounds/commit → { roundId, commitHex, nonce }
- POST /api/rounds/:id/start { clientSeed, betCents, dropColumn } → { roundId, rows, pegMapHash, binIndex, payoutMultiplier, path }
- POST /api/rounds/:id/reveal → { serverSeed, revealedAt }
- GET /api/rounds/detail/:id → full round details (server seed hidden until revealed)
- GET /api/verify?server_seed&client_seed&nonce&drop_column → { commitHex, combinedSeed, pegMapHash, binIndex, path }

Tech Choices
- Backend: FastAPI + MongoDB (provided), Python
- Frontend: React + Vite + Tailwind
- PRNG: xorshift32

How to run
- Servers are auto‑started in this environment. Locally, set DATABASE_URL and DATABASE_NAME.

AI Usage
- Used AI to scaffold endpoints, deterministic engine, and documentation. Prompts summarized in repo discussion.

Tests
- To be added: vectors for combiner/PRNG and replay determinism.
