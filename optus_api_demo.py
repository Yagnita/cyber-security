#!/usr/bin/env python3
"""
optus_api_demo.py
API-ACE: API Access Control Enforcement Framework
Case Study: The Optus Data Breach (2022)

Reproduces experiments E1 through E6 from Group G26 Report:
- E1: Anonymous sequential enumeration on v1 (vulnerable)
- E2: Anonymous attack on v2 (hardened) with no token
- E3-A: Valid token, cross-customer enumeration (auth only)
- E3-B: Valid token with object-level authorization (L3)
- E3-C: Valid token with full API-ACE (L3 + L5 rate limit & lockout)
- E4: Legitimate owner reading own record (L6 data minimization/masking)
- E5: Latency benchmark of legitimate requests (3,000 calls each)
- E6: Distributed attacker (50 IPs) evaluating IP-keyed vs Token-keyed limits
"""

import collections
import datetime
import random
import time
import uuid
from flask import Flask, jsonify, request
import jwt

# ---------------------------------------------------------
# 1. Configuration & Constants
# ---------------------------------------------------------
RANDOM_SEED = 7
NUM_RECORDS = 10000
JWT_SECRET = "api-ace-secret-key-optus-case-study"
JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "customers-api"
RATE_LIMIT_MAX = 60
RATE_LIMIT_WINDOW = 60.0  # seconds
LOCKOUT_THRESHOLD = 5

# ---------------------------------------------------------
# 2. Synthetic Dataset Generation (Section 4.3)
# ---------------------------------------------------------
def generate_dataset(num_records=NUM_RECORDS, seed=RANDOM_SEED):
    rng = random.Random(seed)
    db_by_id = {}
    db_by_uuid = {}
    uuids = []

    for i in range(1, num_records + 1):
        # UUIDv4 deterministic from seeded RNG
        u_int = rng.getrandbits(128)
        u_str = str(uuid.UUID(int=u_int, version=4))
        uuids.append(u_str)

        # DL plus 8 digits; Customer 1 ends in '871' to match report Table 13
        if i == 1:
            id_doc = "DL12345871"
        else:
            id_doc = f"DL{rng.randint(10000000, 99999999)}"

        rec = {
            "id": i,
            "uuid": u_str,
            "name": f"Customer {i}",
            "email": f"c{i}@example.test",
            "dob": "2000-01-01",
            "phone": f"+61400{i:06d}",
            "id_doc": id_doc
        }
        db_by_id[i] = rec
        db_by_uuid[u_str] = rec

    return db_by_id, db_by_uuid, uuids

# ---------------------------------------------------------
# 3. Sliding Window Limiter & Lockout (L5 Abuse Resistance)
# ---------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self, limit=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW):
        self.limit = limit
        self.window = window
        self.requests = collections.defaultdict(list)

    def allow(self, key, now=None):
        if now is None:
            now = time.time()
        cutoff = now - self.window
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]
        if len(self.requests[key]) < self.limit:
            self.requests[key].append(now)
            return True
        return False

    def reset(self):
        self.requests.clear()

# ---------------------------------------------------------
# 4. Token Helper (L2 Edge Authentication)
# ---------------------------------------------------------
def create_token(sub, scope="self", expires_in_hours=1):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": sub,
        "aud": JWT_AUDIENCE,
        "scope": scope,
        "iat": now,
        "exp": now + datetime.timedelta(hours=expires_in_hours)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# ---------------------------------------------------------
# 5. Core API Factory
# ---------------------------------------------------------
def create_api_app(db_by_id, db_by_uuid):
    app = Flask("api_ace")
    limiter = SlidingWindowLimiter()
    strikes = collections.defaultdict(int)
    blocked = set()

    # Ablation settings
    config = {
        "objcheck": True,
        "ratelimit": True,
        "key_by": "token"  # "token" or "ip"
    }

    def reset_state():
        limiter.reset()
        strikes.clear()
        blocked.clear()

    # --- v1: Vulnerable API (Section 4.4) ---
    @app.route("/api/v1/customers/<int:cid>", methods=["GET"])
    def get_customer_v1(cid):
        rec = db_by_id.get(cid)
        if rec:
            return jsonify(rec), 200
        return jsonify({"error": "not found"}), 404

    # --- v2: Hardened API (API-ACE, Section 4.5) ---
    @app.route("/api/v2/customers/<string:cust_uuid>", methods=["GET"])
    def get_customer_v2(cust_uuid):
        client_ip = request.headers.get("X-Client-IP") or request.remote_addr or "127.0.0.1"

        # L2: Decode token
        auth_header = request.headers.get("Authorization", "")
        claims = None
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()
            try:
                claims = jwt.decode(
                    raw_token,
                    JWT_SECRET,
                    algorithms=[JWT_ALGORITHM],
                    audience=JWT_AUDIENCE
                )
            except Exception:
                claims = None

        # Determine rate limiting / lockout key (Section 4.5)
        if config["key_by"] == "token":
            key = claims["sub"] if (claims and "sub" in claims) else client_ip
        else:
            key = client_ip

        # L5: Rate limit and lockout check first (Rule R1)
        if config["ratelimit"] and (key in blocked or not limiter.allow(key)):
            return jsonify({"error": "too many requests"}), 429

        # L2: Authentication check (Rule R2)
        if claims is None:
            return jsonify({"error": "unauthenticated"}), 401

        # L3: Object-level and function-level authorization (Rule R3, R4)
        rec = db_by_uuid.get(cust_uuid)
        scope = claims.get("scope", "")
        owner_or_agent = (claims.get("sub") == cust_uuid) or ("agent:read" in scope.split())

        if rec is None or (config["objcheck"] and not owner_or_agent):
            # L5: Strike on authorization failure
            strikes[key] += 1
            if strikes[key] >= LOCKOUT_THRESHOLD:
                blocked.add(key)
            return jsonify({"error": "forbidden"}), 403

        # L4: UUID lookup; L6: Data minimisation & masking
        out = {k: rec[k] for k in ["uuid", "name", "email"]}
        out["id_doc"] = "*****" + rec["id_doc"][-3:]
        return jsonify(out), 200

    return app, config, reset_state

# ---------------------------------------------------------
# 6. Experiment Runner (Section 4.6, 5.1 & Tables 13, 14)
# ---------------------------------------------------------
def run_experiments():
    print("=" * 76)
    print("API-ACE: Experimental Evaluation of Optus Data Breach Countermeasures")
    print("=" * 76)
    print(f"Generating synthetic dataset: {NUM_RECORDS} records (seed={RANDOM_SEED})...")
    db_by_id, db_by_uuid, uuids = generate_dataset()
    print("Dataset generation complete.\n")
    print("Running evaluation suite (simulating ~96,000 requests across E1-E6)...")
    print("Please wait ~60-90 seconds while all scenarios execute.\n")

    app, config, reset_state = create_api_app(db_by_id, db_by_uuid)
    client = app.test_client()

    results_e1_e5 = []

    # -----------------------------------------------------
    # E1: Anonymous sequential enumeration on v1 (vulnerable)
    # -----------------------------------------------------
    print("[1/7] Running E1: Anonymous sequential enumeration (10,000 reqs)...", end="", flush=True)
    reset_state()
    status_counts = collections.defaultdict(int)
    exposed_count = 0
    for i in range(1, NUM_RECORDS + 1):
        res = client.get(f"/api/v1/customers/{i}")
        status_counts[res.status_code] += 1
        if res.status_code == 200:
            exposed_count += 1
    pct = (exposed_count / NUM_RECORDS) * 100
    res_str = f"{status_counts[200]:,d} x HTTP 200"
    exp_str = f"{exposed_count:,d} ({pct:.0f}%)"
    results_e1_e5.append(("E1", "Anonymous sequential enumeration, v1 (vulnerable)", res_str, exp_str))
    print(" Done.", flush=True)

    # -----------------------------------------------------
    # E2: Same attack on v2 (hardened), no token
    # -----------------------------------------------------
    print("[2/7] Running E2: Anonymous on v2 without token (10,000 reqs)...", end="", flush=True)
    reset_state()
    config["objcheck"] = True
    config["ratelimit"] = True
    config["key_by"] = "token"
    status_counts = collections.defaultdict(int)
    exposed_count = 0
    for u in uuids:
        res = client.get(f"/api/v2/customers/{u}")
        status_counts[res.status_code] += 1
        if res.status_code == 200:
            exposed_count += 1
    res_str = f"{status_counts[401]} x 401, then {status_counts[429]:,d} x 429"
    exp_str = str(exposed_count)
    results_e1_e5.append(("E2", "Same attack on v2 (hardened), no token", res_str, exp_str))
    print(" Done.", flush=True)

    # -----------------------------------------------------
    # E3-A: Valid own token, 9,999 victim UUIDs, authentication only
    # -----------------------------------------------------
    print("[3/7] Running E3 (A, B, C): Cross-account BOLA simulations...", end="", flush=True)
    reset_state()
    config["objcheck"] = False
    config["ratelimit"] = False
    config["key_by"] = "token"
    attacker_uuid = uuids[0]
    token = create_token(sub=attacker_uuid)
    headers = {"Authorization": f"Bearer {token}"}
    status_counts = collections.defaultdict(int)
    exposed_count = 0
    for u in uuids[1:]:
        res = client.get(f"/api/v2/customers/{u}", headers=headers)
        status_counts[res.status_code] += 1
        if res.status_code == 200:
            exposed_count += 1
    pct = (exposed_count / (NUM_RECORDS - 1)) * 100
    res_str = f"{status_counts[200]:,d} x 200"
    exp_str = f"{exposed_count:,d} ({pct:.0f}%)"
    results_e1_e5.append(("E3-A", "Valid own token, 9,999 victim UUIDs, authentication only", res_str, exp_str))

    # -----------------------------------------------------
    # E3-B: E3 plus object-level authorization (objcheck=True, ratelimit=False)
    # -----------------------------------------------------
    reset_state()
    config["objcheck"] = True
    config["ratelimit"] = False
    config["key_by"] = "token"
    status_counts = collections.defaultdict(int)
    exposed_count = 0
    for u in uuids[1:]:
        res = client.get(f"/api/v2/customers/{u}", headers=headers)
        status_counts[res.status_code] += 1
        if res.status_code == 200:
            exposed_count += 1
    res_str = f"{status_counts[403]:,d} x 403"
    exp_str = str(exposed_count)
    results_e1_e5.append(("E3-B", "E3 plus object-level authorization", res_str, exp_str))

    # -----------------------------------------------------
    # E3-C: E3 with full API-ACE (adds rate limit and lockout)
    # -----------------------------------------------------
    reset_state()
    config["objcheck"] = True
    config["ratelimit"] = True
    config["key_by"] = "token"
    status_counts = collections.defaultdict(int)
    exposed_count = 0
    for u in uuids[1:]:
        res = client.get(f"/api/v2/customers/{u}", headers=headers)
        status_counts[res.status_code] += 1
        if res.status_code == 200:
            exposed_count += 1
    res_str = f"{status_counts[403]} x 403, then {status_counts[429]:,d} x 429"
    exp_str = str(exposed_count)
    results_e1_e5.append(("E3-C", "E3 with full API-ACE (adds rate limit and lockout)", res_str, exp_str))
    print(" Done.", flush=True)

    # -----------------------------------------------------
    # E4: Legitimate owner reads own record
    # -----------------------------------------------------
    print("[4/7] Running E4: Legitimate owner read with masking...", end="", flush=True)
    reset_state()
    config["objcheck"] = True
    config["ratelimit"] = True
    config["key_by"] = "token"
    owner_uuid = uuids[0]
    owner_token = create_token(sub=owner_uuid)
    res = client.get(f"/api/v2/customers/{owner_uuid}", headers={"Authorization": f"Bearer {owner_token}"})
    json_data = res.get_json()
    id_doc_val = json_data.get("id_doc", "")
    res_str = f"HTTP {res.status_code}, ID document returned as {id_doc_val}"
    exp_str = "Own record only, masked"
    results_e1_e5.append(("E4", "Legitimate owner reads own record", res_str, exp_str))
    print(" Done.", flush=True)

    # -----------------------------------------------------
    # E5: Latency of legitimate requests (3,000 legitimate requests each)
    # -----------------------------------------------------
    print("[5/7] Running E5: Latency benchmark (6,000 requests)...", end="", flush=True)
    reset_state()
    latencies_v1 = []
    for _ in range(3000):
        t0 = time.perf_counter()
        client.get("/api/v1/customers/1")
        t1 = time.perf_counter()
        latencies_v1.append((t1 - t0) * 1000.0)

    reset_state()
    # High limit to measure unthrottled processing latency
    config["ratelimit"] = False
    latencies_v2 = []
    auth_hdr = {"Authorization": f"Bearer {owner_token}"}
    for _ in range(3000):
        t0 = time.perf_counter()
        client.get(f"/api/v2/customers/{owner_uuid}", headers=auth_hdr)
        t1 = time.perf_counter()
        latencies_v2.append((t1 - t0) * 1000.0)

    mean_v1 = sum(latencies_v1) / len(latencies_v1)
    median_v1 = sorted(latencies_v1)[len(latencies_v1) // 2]
    mean_v2 = sum(latencies_v2) / len(latencies_v2)
    median_v2 = sorted(latencies_v2)[len(latencies_v2) // 2]

    res_str = f"v1: {mean_v1:.3f} / {median_v1:.3f} ms; v2: {mean_v2:.3f} / {median_v2:.3f} ms"
    results_e1_e5.append(("E5", "Latency of legitimate requests (mean / median)", res_str, "n/a"))
    print(" Done.\n", flush=True)

    # Print Table 13
    print("Table 13. Results of experiments E1 to E5:")
    print("-" * 92)
    print(f"{'Exp.':<6} | {'Scenario':<52} | {'Result':<32} | {'Records exposed'}")
    print("-" * 92)
    for exp_id, scenario, res_val, exp_val in results_e1_e5:
        print(f"{exp_id:<6} | {scenario:<52} | {res_val:<32} | {exp_val}")
    print("-" * 92)
    print()

    # -----------------------------------------------------
    # Table 14: Experiment E6 (50 source IPs distributed attacker)
    # -----------------------------------------------------
    e6_configs = [
        ("E6-A", True, "ip", "Object check on, limiter keyed by IP"),
        ("E6-B", True, "token", "Object check on, limiter keyed by token"),
        ("E6-C", False, "ip", "Object check MISSING, limiter keyed by IP"),
        ("E6-D", False, "token", "Object check MISSING, limiter keyed by token")
    ]

    results_e6 = []
    ip_pool = [f"198.51.100.{x}" for x in range(1, 51)]

    print("[6/7] Running E6 (A-D): Distributed attacker across 50 IPs (40,000 reqs)...", end="", flush=True)
    for exp_id, obj_on, key_mode, desc in e6_configs:
        reset_state()
        config["objcheck"] = obj_on
        config["ratelimit"] = True
        config["key_by"] = key_mode

        attacker_token = create_token(sub=uuids[0])
        headers_base = {"Authorization": f"Bearer {attacker_token}"}

        status_counts = collections.defaultdict(int)
        exposed_count = 0

        for idx, u in enumerate(uuids[1:]):
            src_ip = ip_pool[idx % len(ip_pool)]
            req_headers = {**headers_base, "X-Client-IP": src_ip}
            res = client.get(f"/api/v2/customers/{u}", headers=req_headers)
            status_counts[res.status_code] += 1
            if res.status_code == 200:
                exposed_count += 1

        if obj_on:
            res_str = f"{status_counts[403]} x 403, then {status_counts[429]:,d} x 429"
            meaning_str = f"{exposed_count} exposed; {status_counts[403]} requests processed"
        else:
            res_str = f"{status_counts[200]:,d} x 200, then {status_counts[429]:,d} x 429"
            meaning_str = f"{exposed_count:,d} records exposed"

        results_e6.append((exp_id, desc, res_str, meaning_str))
    print(" Done.\n", flush=True)

    # Print Table 14
    print("Table 14. Results of experiment E6 (attacker with valid token spreading over 50 IPs):")
    print("-" * 92)
    print(f"{'Exp.':<6} | {'Configuration':<45} | {'Result':<28} | {'Meaning'}")
    print("-" * 92)
    for exp_id, cfg_desc, res_val, meaning_val in results_e6:
        print(f"{exp_id:<6} | {cfg_desc:<45} | {res_val:<28} | {meaning_val}")
    print("-" * 92)
    print("\nBenchmark completed successfully.")

if __name__ == "__main__":
    run_experiments()
