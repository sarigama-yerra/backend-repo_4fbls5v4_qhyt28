import os
import hashlib
import hmac
import secrets
import json
from typing import List, Optional, Literal, Tuple
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from math import comb, floor
from datetime import datetime, timezone
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI(title="Plinko Lab API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Generic Helpers ----------------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hmac_sha256_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


# ---------------------- Engine v1 (HMAC-based) ----------------------
# Existing simple engine kept for backwards-compatibility

def rand_unit_from_hex(hexstr: str) -> float:
    # Use first 13 hex chars -> 52 bits of precision for a [0,1) float
    frac_bits = int(hexstr[:13], 16)
    return frac_bits / (16 ** 13)


def plinko_rng_bits(server_seed: str, client_seed: str, nonce: int, rows: int) -> List[float]:
    values = []
    for i in range(rows):
        h = hmac_sha256_hex(server_seed, f"{client_seed}:{nonce}:{i}")
        values.append(rand_unit_from_hex(h))
    return values


def plinko_path_from_rng(values: List[float]) -> List[str]:
    # R if >= 0.5 else L
    return ["R" if v >= 0.5 else "L" for v in values]


def bucket_index_from_path(path: List[str]) -> int:
    # Number of rights equals bucket index
    return sum(1 for step in path if step == "R")


def compute_multipliers(rows: int, risk: Literal["low", "medium", "high"], house_edge: float = 0.02) -> List[float]:
    if rows < 8 or rows > 20:
        # keep reasonable bounds
        raise HTTPException(status_code=400, detail="rows must be between 8 and 20")

    # Risk shaping exponent: controls variance, we renormalize to target EV
    alpha_map = {"low": -0.5, "medium": 0.0, "high": 1.0}
    alpha = alpha_map.get(risk, 0.0)

    n = rows
    probs = [comb(n, k) / (2 ** n) for k in range(n + 1)]
    base = [1.0 / p for p in probs]  # fair payout multipliers (EV = 1)

    center = n / 2.0
    # Shape weights: boost edges for high risk, boost center for low risk
    weights = [
        ((abs(k - center) + 1.0) / (center + 1.0)) ** alpha for k in range(n + 1)
    ]

    shaped = [b * w for b, w in zip(base, weights)]

    # Renormalize so expected value equals (1 - house_edge)
    ev = sum(p * m for p, m in zip(probs, shaped))
    factor = (1.0 - house_edge) / ev
    multipliers = [m * factor for m in shaped]
    return multipliers


def simulate_plinko(server_seed: str, client_seed: str, nonce: int, rows: int, risk: str):
    rng_values = plinko_rng_bits(server_seed, client_seed, nonce, rows)
    path = plinko_path_from_rng(rng_values)
    bucket = bucket_index_from_path(path)
    mults = compute_multipliers(rows, risk)  # may raise HTTPException if invalid
    multiplier = mults[bucket]
    return {
        "rng_values": rng_values,
        "path": path,
        "bucket": bucket,
        "multipliers": mults,
        "multiplier": multiplier,
    }


# ---------------------- Engine v2 (Deterministic Discrete per spec) ----------------------
# Implements commitHex, combinedSeed, peg map generation with xorshift32 PRNG, path decisions and hashing

class XorShift32:
    def __init__(self, seed: int):
        if seed == 0:
            seed = 0x6D2B79F5  # avoid zero lock state
        self.state = seed & 0xFFFFFFFF

    def next_u32(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x & 0xFFFFFFFF
        return self.state

    def rand(self) -> float:
        # Returns float in [0,1)
        return self.next_u32() / 4294967296.0  # 2**32


def seed_from_combined_hex(combined_hex: str) -> int:
    # First 4 bytes (8 hex chars), big-endian
    return int(combined_hex[:8], 16)


def stable_float6(x: float) -> float:
    # Round to 6 decimals for stable hashing and representation
    return float(f"{x:.6f}")


def stable_json(data) -> str:
    # Deterministic JSON: ensure floats as 6dp strings in pegMap
    def default(o):
        if isinstance(o, float):
            return float(f"{o:.6f}")
        raise TypeError
    return json.dumps(data, separators=(",", ":"))


def generate_peg_map(rows: int, prng: XorShift32) -> List[List[float]]:
    peg_map: List[List[float]] = []
    for r in range(rows):
        row = []
        for _ in range(r + 1):
            rnd = prng.rand()
            left_bias = 0.5 + (rnd - 0.5) * 0.2  # in [0.4, 0.6]
            row.append(stable_float6(left_bias))
        peg_map.append(row)
    return peg_map


def peg_map_hash(peg_map: List[List[float]]) -> str:
    # Hash JSON of peg_map with 6dp floats
    s = json.dumps(peg_map, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()


def simulate_discrete_engine(server_seed: str, client_seed: str, nonce: str, rows: int, drop_column: int) -> Tuple[dict, List[str]]:
    if rows != 12:
        # The spec uses 12; allow other values but default 12
        rows = 12
    # commit and combined
    commit_hex = sha256_hex(f"{server_seed}:{nonce}")
    combined_hex = sha256_hex(f"{server_seed}:{client_seed}:{nonce}")
    prng = XorShift32(seed_from_combined_hex(combined_hex))
    # peg map then path decisions share one PRNG stream
    peg_map = generate_peg_map(rows, prng)
    peg_hash = peg_map_hash(peg_map)

    # path decisions
    pos = 0
    path: List[str] = []
    center = rows // 2
    adj = (drop_column - center) * 0.01

    for r in range(rows):
        peg_idx = pos if pos < (r + 1) else r
        base_bias = peg_map[r][peg_idx]
        bias_prime = max(0.0, min(1.0, base_bias + adj))
        rnd = prng.rand()
        if rnd < bias_prime:
            path.append("L")
        else:
            path.append("R")
            pos += 1

    result = {
        "commitHex": commit_hex,
        "combinedSeed": combined_hex,
        "pegMapHash": peg_hash,
        "binIndex": pos,
        "pegMap": peg_map,
        "path": path,
        "rows": rows,
        "dropColumn": drop_column,
    }
    return result, path


# ---------------------- Data Models ----------------------

class CommitResponse(BaseModel):
    round_id: str
    server_seed_hash: str
    message: str = "commit_created"


class RevealRequest(BaseModel):
    round_id: str
    client_seed: str
    nonce: int = Field(0, ge=0)
    rows: int = Field(16, ge=8, le=20)
    risk: Literal["low", "medium", "high"] = "medium"
    bet_amount: float = Field(1.0, gt=0)


class RevealResponse(BaseModel):
    round_id: str
    server_seed_hash: str
    server_seed: str
    client_seed: str
    nonce: int
    rows: int
    risk: str
    path: List[str]
    bucket: int
    multiplier: float
    payout: float
    multipliers: List[float]
    rng_values: List[float]
    created_at: datetime


class VerifyQuery(BaseModel):
    server_seed: str
    client_seed: str
    nonce: int = 0
    rows: int = 16
    risk: Literal["low", "medium", "high"] = "medium"
    bet_amount: Optional[float] = None


# New protocol models
class CommitV2Response(BaseModel):
    roundId: str
    commitHex: str
    nonce: str
    status: str = "CREATED"


class StartV2Request(BaseModel):
    clientSeed: str
    betCents: int = Field(ge=0)
    dropColumn: int = Field(0, ge=0, le=12)


class StartV2Response(BaseModel):
    roundId: str
    rows: int
    pegMapHash: str
    binIndex: int
    payoutMultiplier: float
    path: List[str]
    status: str


class RevealV2Response(BaseModel):
    roundId: str
    serverSeed: str
    revealedAt: datetime
    status: str


# ---------------------- API Routes ----------------------

@app.get("/")
def read_root():
    return {"message": "Plinko Lab Backend Ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, "name") else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ---------- Existing simple endpoints (kept) ----------

@app.post("/api/commit", response_model=CommitResponse)
def commit_round():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    server_seed = secrets.token_hex(32)
    server_seed_hash = sha256_hex(server_seed)

    doc = {
        "type": "plinko_round",
        "status": "committed",
        "server_seed": server_seed,  # stored but never exposed until reveal
        "server_seed_hash": server_seed_hash,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    round_id = db["plinko_round"].insert_one(doc).inserted_id

    return CommitResponse(round_id=str(round_id), server_seed_hash=server_seed_hash)


@app.post("/api/reveal", response_model=RevealResponse)
def reveal_round(payload: RevealRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    try:
        _id = ObjectId(payload.round_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid round_id")

    doc = db["plinko_round"].find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="Round not found")

    if doc.get("status") not in ("committed", "revealed"):
        raise HTTPException(status_code=400, detail="Invalid round status")

    server_seed: str = doc["server_seed"]
    server_seed_hash: str = doc["server_seed_hash"]
    # Verify commitment integrity
    if sha256_hex(server_seed) != server_seed_hash:
        raise HTTPException(status_code=400, detail="Commitment mismatch")

    sim = simulate_plinko(
        server_seed=server_seed,
        client_seed=payload.client_seed,
        nonce=payload.nonce,
        rows=payload.rows,
        risk=payload.risk,
    )

    payout = payload.bet_amount * sim["multiplier"]

    update = {
        "status": "revealed",
        "client_seed": payload.client_seed,
        "nonce": payload.nonce,
        "rows": payload.rows,
        "risk": payload.risk,
        "path": sim["path"],
        "bucket": sim["bucket"],
        "multiplier": sim["multiplier"],
        "multipliers": sim["multipliers"],
        "rng_values": sim["rng_values"],
        "bet_amount": payload.bet_amount,
        "payout": payout,
        "revealed_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    db["plinko_round"].update_one({"_id": _id}, {"$set": update})

    return RevealResponse(
        round_id=str(_id),
        server_seed_hash=server_seed_hash,
        server_seed=server_seed,
        client_seed=payload.client_seed,
        nonce=payload.nonce,
        rows=payload.rows,
        risk=payload.risk,
        path=sim["path"],
        bucket=sim["bucket"],
        multiplier=sim["multiplier"],
        payout=payout,
        multipliers=sim["multipliers"],
        rng_values=sim["rng_values"],
        created_at=doc.get("created_at", datetime.now(timezone.utc)),
    )


@app.get("/api/rounds")
def list_rounds(limit: int = 20):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    cursor = db["plinko_round"].find().sort("created_at", -1).limit(int(max(1, min(100, limit))))
    def to_public(d):
        d["id"] = str(d.pop("_id"))
        if "server_seed" in d and d.get("status") != "revealed":
            d.pop("server_seed", None)
        return d
    return [to_public(doc) for doc in cursor]


@app.get("/api/rounds/{round_id}")
def get_round(round_id: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        _id = ObjectId(round_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid round_id")
    doc = db["plinko_round"].find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    if "server_seed" in doc and doc.get("status") != "revealed":
        doc.pop("server_seed", None)
    return doc


# -------------- New endpoints for Deterministic Discrete Engine --------------

@app.post("/api/rounds/commit", response_model=CommitV2Response)
def v2_commit_round():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    server_seed = secrets.hex_bytes(32).hex()
    nonce = str(secrets.randbelow(10**9))
    commit_hex = sha256_hex(f"{server_seed}:{nonce}")

    doc = {
        "type": "round",
        "status": "CREATED",
        "serverSeed": server_seed,
        "nonce": nonce,
        "commitHex": commit_hex,
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }
    inserted_id = db["round"].insert_one(doc).inserted_id
    return CommitV2Response(roundId=str(inserted_id), commitHex=commit_hex, nonce=nonce)


@app.post("/api/rounds/{round_id}/start", response_model=StartV2Response)
def v2_start_round(round_id: str, payload: StartV2Request):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        _id = ObjectId(round_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid round id")

    doc = db["round"].find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="Round not found")

    server_seed = doc["serverSeed"]
    nonce = doc["nonce"]
    rows = 12

    sim, path = simulate_discrete_engine(
        server_seed=server_seed,
        client_seed=payload.clientSeed,
        nonce=nonce,
        rows=rows,
        drop_column=payload.dropColumn,
    )

    # Simple symmetric paytable: edges higher, center lower (example constants)
    # Here we shape using binomial probability reciprocal, then normalize EV~=1
    probs = [comb(rows, k) / (2 ** rows) for k in range(rows + 1)]
    base = [1.0 / p for p in probs]
    ev = sum(p * m for p, m in zip(probs, base))
    factor = 1.0 / ev
    paytable = [m * factor for m in base]

    mult = float(paytable[sim["binIndex"]])

    update = {
        "status": "STARTED",
        "clientSeed": payload.clientSeed,
        "combinedSeed": sim["combinedSeed"],
        "pegMapHash": sim["pegMapHash"],
        "rows": rows,
        "dropColumn": payload.dropColumn,
        "binIndex": sim["binIndex"],
        "payoutMultiplier": mult,
        "betCents": payload.betCents,
        "pathJson": sim["path"],
        "updatedAt": datetime.now(timezone.utc),
    }
    db["round"].update_one({"_id": _id}, {"$set": update})

    return StartV2Response(
        roundId=round_id,
        rows=rows,
        pegMapHash=sim["pegMapHash"],
        binIndex=sim["binIndex"],
        payoutMultiplier=mult,
        path=sim["path"],
        status="STARTED",
    )


@app.post("/api/rounds/{round_id}/reveal", response_model=RevealV2Response)
def v2_reveal_round(round_id: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        _id = ObjectId(round_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid round id")

    doc = db["round"].find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="Round not found")

    if doc.get("status") not in ("STARTED", "CREATED", "REVEALED"):
        raise HTTPException(status_code=400, detail="Invalid status transition")

    revealed_at = datetime.now(timezone.utc)
    db["round"].update_one({"_id": _id}, {"$set": {"status": "REVEALED", "revealedAt": revealed_at}})

    return RevealV2Response(roundId=round_id, serverSeed=doc["serverSeed"], revealedAt=revealed_at, status="REVEALED")


@app.get("/api/rounds/detail/{round_id}")
def v2_get_round(round_id: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        _id = ObjectId(round_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid round id")
    doc = db["round"].find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    if doc.get("status") != "REVEALED":
        doc.pop("serverSeed", None)
    return doc


@app.get("/api/verify")
def verify(server_seed: str, client_seed: str, nonce: str = "0", rows: int = 12, drop_column: int = 6):
    # Deterministic discrete engine verify
    sim, _ = simulate_discrete_engine(server_seed=server_seed, client_seed=client_seed, nonce=nonce, rows=rows, drop_column=drop_column)
    return {
        "commitHex": sim["commitHex"],
        "combinedSeed": sim["combinedSeed"],
        "pegMapHash": sim["pegMapHash"],
        "binIndex": sim["binIndex"],
        "rows": sim["rows"],
        "dropColumn": sim["dropColumn"],
        "path": sim["path"],
    }


@app.get("/api/multipliers")
def get_multipliers(rows: int = 16, risk: str = "medium"):
    mults = compute_multipliers(rows, risk)
    return {"rows": rows, "risk": risk, "multipliers": mults}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
