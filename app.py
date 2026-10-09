#!/usr/bin/env python3
"""
app.py
API-ACE: API Access Control Enforcement Web Application & SOC Dashboard
Course: Cyber Security - Case Study: Optus Data Breach (2022)
Group: G26 (Anushka Tandon, Yagnita Patel, Laxmi Sah)

Exposes:
- /api/v1/customers/<int:cid>          (Vulnerable Optus-style API)
- /api/v2/customers/<string:cust_uuid> (Hardened API-ACE)
- /api/auth/token                      (JWT generation for testing)
- /api/customers/sample                (Sample customer metadata)
- /api/v2/config                       (View/update ablation settings)
- /api/v2/reset                        (Reset strikes & rate limits)
- /api/logs                            (Structured L7 security audit logs)
- /                                    (Interactive Web SOC & Attack Lab)
"""

import collections
import datetime
import random
import time
import uuid
from flask import Flask, jsonify, request, render_template_string
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

app = Flask(__name__)

# ---------------------------------------------------------
# 2. Synthetic Dataset Generation (Section 4.3)
# ---------------------------------------------------------
def generate_dataset(num_records=NUM_RECORDS, seed=RANDOM_SEED):
    rng = random.Random(seed)
    db_by_id = {}
    db_by_uuid = {}
    uuids = []

    for i in range(1, num_records + 1):
        u_int = rng.getrandbits(128)
        u_str = str(uuid.UUID(int=u_int, version=4))
        uuids.append(u_str)

        # Customer 1 ends with '871' matching Table 13 in report
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

DB_BY_ID, DB_BY_UUID, UUID_LIST = generate_dataset()

# ---------------------------------------------------------
# 3. L5 Abuse Resistance: Sliding Window & Lockout
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

limiter = SlidingWindowLimiter()
strikes = collections.defaultdict(int)
blocked = set()

# Ablation flags
config = {
    "objcheck": True,
    "ratelimit": True,
    "key_by": "token"  # "token" or "ip"
}

# ---------------------------------------------------------
# 4. L7 Security Audit Logging
# ---------------------------------------------------------
audit_logs = collections.deque(maxlen=200)

def log_event(endpoint, method, status, client_ip, caller_sub, note):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "endpoint": endpoint,
        "method": method,
        "status": status,
        "ip": client_ip,
        "caller": caller_sub or "anonymous",
        "note": note
    }
    audit_logs.appendleft(entry)

# ---------------------------------------------------------
# 5. Token Helper (L2 Edge Authentication)
# ---------------------------------------------------------
def create_jwt_token(sub, scope="self", expires_in_hours=1):
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
# 6. API v1: Vulnerable Endpoint (Section 4.4)
# ---------------------------------------------------------
@app.route("/api/v1/customers/<int:cid>", methods=["GET"])
def get_customer_v1(cid):
    client_ip = request.headers.get("X-Client-IP") or request.remote_addr or "127.0.0.1"
    rec = DB_BY_ID.get(cid)
    if rec:
        log_event(f"/api/v1/customers/{cid}", "GET", 200, client_ip, None, "Vulnerable API: Full unmasked record leaked")
        return jsonify(rec), 200
    log_event(f"/api/v1/customers/{cid}", "GET", 404, client_ip, None, "Vulnerable API: Customer not found")
    return jsonify({"error": "not found"}), 404

# ---------------------------------------------------------
# 7. API v2: Hardened API-ACE Endpoint (Section 4.5)
# ---------------------------------------------------------
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
        except Exception as e:
            claims = None

    # Determine key for rate limiting & lockout
    if config["key_by"] == "token":
        key = claims["sub"] if (claims and "sub" in claims) else client_ip
    else:
        key = client_ip

    caller_sub = claims.get("sub") if claims else None

    # L5: Abuse resistance & lockout check (Rule R1)
    if config["ratelimit"] and (key in blocked or not limiter.allow(key)):
        reason = "Lockout active (exceeded strikes)" if key in blocked else "Sliding window rate limit exceeded"
        log_event(f"/api/v2/customers/{cust_uuid[:8]}...", "GET", 429, client_ip, caller_sub, f"L5 Blocked: {reason}")
        return jsonify({"error": "too many requests"}), 429

    # L2: Edge authentication check (Rule R2)
    if claims is None:
        log_event(f"/api/v2/customers/{cust_uuid[:8]}...", "GET", 401, client_ip, None, "L2 Rejected: Missing or invalid JWT")
        return jsonify({"error": "unauthenticated"}), 401

    # L3: Object-level and function-level authorization (Rule R3, R4)
    rec = DB_BY_UUID.get(cust_uuid)
    scope = claims.get("scope", "")
    owner_or_agent = (claims.get("sub") == cust_uuid) or ("agent:read" in scope.split())

    if rec is None or (config["objcheck"] and not owner_or_agent):
        strikes[key] += 1
        lockout_msg = ""
        if strikes[key] >= LOCKOUT_THRESHOLD:
            blocked.add(key)
            lockout_msg = " [Lockout triggered: 5 strikes reached]"
        
        log_event(f"/api/v2/customers/{cust_uuid[:8]}...", "GET", 403, client_ip, caller_sub, 
                  f"L3 Denied: BOLA violation (strike {strikes[key]}/{LOCKOUT_THRESHOLD}){lockout_msg}")
        return jsonify({"error": "forbidden"}), 403

    # L4: UUID validated; L6: Data minimisation & masking
    out = {k: rec[k] for k in ["uuid", "name", "email"]}
    out["id_doc"] = "*****" + rec["id_doc"][-3:]
    
    role_info = "Staff agent:read" if "agent:read" in scope else "Record owner"
    log_event(f"/api/v2/customers/{cust_uuid[:8]}...", "GET", 200, client_ip, caller_sub, f"L6 Success: Authorized as {role_info}, masked")
    return jsonify(out), 200

# ---------------------------------------------------------
# 8. Helper & Management Endpoints
# ---------------------------------------------------------
@app.route("/api/auth/token", methods=["POST", "GET"])
def issue_token():
    """Generates signed JWT token for testing."""
    data = request.get_json(silent=True) or request.args
    sub = data.get("sub") or UUID_LIST[0]
    scope = data.get("scope") or "self"
    token = create_jwt_token(sub=sub, scope=scope)
    return jsonify({
        "token": token,
        "sub": sub,
        "scope": scope,
        "audience": JWT_AUDIENCE,
        "algorithm": JWT_ALGORITHM
    })

@app.route("/api/customers/sample", methods=["GET"])
def get_sample_customers():
    """Provides sample customer metadata for testing."""
    return jsonify({
        "customer_1": {
            "id": DB_BY_ID[1]["id"],
            "uuid": DB_BY_ID[1]["uuid"],
            "name": DB_BY_ID[1]["name"],
            "email": DB_BY_ID[1]["email"]
        },
        "customer_2": {
            "id": DB_BY_ID[2]["id"],
            "uuid": DB_BY_ID[2]["uuid"],
            "name": DB_BY_ID[2]["name"],
            "email": DB_BY_ID[2]["email"]
        },
        "total_records": NUM_RECORDS
    })

@app.route("/api/v2/config", methods=["GET", "POST"])
def manage_config():
    """Inspect or update ablation flags."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "objcheck" in data:
            config["objcheck"] = bool(data["objcheck"])
        if "ratelimit" in data:
            config["ratelimit"] = bool(data["ratelimit"])
        if "key_by" in data and data["key_by"] in ("token", "ip"):
            config["key_by"] = str(data["key_by"])
    return jsonify({
        "config": config,
        "active_strikes_count": len(strikes),
        "blocked_keys_count": len(blocked)
    })

@app.route("/api/v2/reset", methods=["POST"])
def reset_defense_state():
    """Resets strikes, lockout blocks, and rate limiter."""
    limiter.reset()
    strikes.clear()
    blocked.clear()
    log_event("/api/v2/reset", "POST", 200, "127.0.0.1", "admin", "Defense state reset: strikes and lockouts cleared")
    return jsonify({"status": "reset successful"})

@app.route("/api/logs", methods=["GET"])
def get_audit_logs():
    """Returns recent L7 security audit logs."""
    return jsonify(list(audit_logs))

# ---------------------------------------------------------
# 9. Interactive Web Dashboard & Attack Lab (Root UI)
# ---------------------------------------------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API-ACE | Optus Breach Security Lab</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0e17;
            --bg-card: #131c2e;
            --bg-card-hover: #19263f;
            --border-color: #243552;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, sans-serif;
            padding: 24px;
            min-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }
        .title h1 {
            font-size: 24px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: #1e3a8a;
            color: #60a5fa;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .subtitle {
            color: var(--text-muted);
            font-size: 13px;
            margin-top: 4px;
        }
        .group-tag {
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }
        .layers-bar {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 8px;
            margin-bottom: 24px;
        }
        .layer-item {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px;
            text-align: center;
        }
        .layer-item.active {
            border-color: #3b82f6;
            background: rgba(59, 130, 246, 0.1);
        }
        .layer-num { font-size: 10px; color: var(--accent-cyan); font-weight: 700; text-transform: uppercase; }
        .layer-name { font-size: 12px; font-weight: 600; margin-top: 2px; }

        .grid-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }
        .card-title {
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn {
            background: #2563eb;
            color: #fff;
            border: none;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn:hover { background: #1d4ed8; }
        .btn-danger { background: #dc2626; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-green { background: #059669; }
        .btn-green:hover { background: #047857; }
        .btn-gray { background: #334155; }
        .btn-gray:hover { background: #475569; }
        .btn-sm { padding: 4px 10px; font-size: 12px; }

        .btn-group { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }

        .mono-box {
            background: #060910;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            line-height: 1.5;
            color: #cbd5e1;
            max-height: 240px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
        }
        .status-200 { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }
        .status-401 { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); }
        .status-403 { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }
        .status-429 { background: rgba(168, 85, 247, 0.2); color: #c084fc; }

        .log-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
        }
        .log-table th {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-muted);
            font-weight: 600;
        }
        .log-table td {
            padding: 8px;
            border-bottom: 1px solid #162238;
        }
        .controls-row {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 16px;
            background: rgba(15, 23, 42, 0.6);
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 13px;
        }
        .switch-label {
            display: flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
        }
    </style>
</head>
<body>

    <div class="header">
        <div class="title">
            <h1>API-ACE Defense Framework <span class="badge">Optus Case Study</span></h1>
            <div class="subtitle">API Access Control Enforcement & BOLA Defense Demonstration</div>
        </div>
        <div class="group-tag">
            <strong>Group G26 | B.Tech CSE</strong><br>
            Anushka Tandon &bull; Yagnita Patel &bull; Laxmi Sah
        </div>
    </div>

    <!-- 7-Layer Architecture Overview -->
    <div class="layers-bar">
        <div class="layer-item active"><div class="layer-num">L1</div><div class="layer-name">Inventory</div></div>
        <div class="layer-item active"><div class="layer-num">L2</div><div class="layer-name">Edge Auth (JWT)</div></div>
        <div class="layer-item active"><div class="layer-num">L3</div><div class="layer-name">Object Authz</div></div>
        <div class="layer-item active"><div class="layer-num">L4</div><div class="layer-name">UUID Opaque</div></div>
        <div class="layer-item active"><div class="layer-num">L5</div><div class="layer-name">Rate & Lockout</div></div>
        <div class="layer-item active"><div class="layer-num">L6</div><div class="layer-name">Masking</div></div>
        <div class="layer-item active"><div class="layer-num">L7</div><div class="layer-name">Audit Logs</div></div>
    </div>

    <!-- Main Comparison Cards -->
    <div class="grid-container">
        
        <!-- Left Column: v1 Vulnerable -->
        <div class="card" style="border-top: 3px solid var(--accent-red);">
            <div class="card-header">
                <div class="card-title" style="color: #f87171;">
                    <span>&bull;</span> API v1: Vulnerable Endpoint (Optus Style)
                </div>
                <span class="badge" style="background:#450a0a; color:#fca5a5;">Unprotected</span>
            </div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
                Sequential integer IDs (<code>/api/v1/customers/&lt;id&gt;</code>) with no authentication or object-level authorization. Exposes full identity documents unmasked.
            </p>
            <div class="btn-group">
                <button class="btn btn-danger" onclick="runV1Test(1)">Enumerate Customer 1</button>
                <button class="btn btn-danger" onclick="runV1Test(2)">Enumerate Customer 2</button>
                <button class="btn btn-gray" onclick="runV1Scrape(5)">Scrape 5 Records</button>
            </div>
            <div class="mono-box" id="v1-response">// Results will appear here...</div>
        </div>

        <!-- Right Column: v2 Hardened API-ACE -->
        <div class="card" style="border-top: 3px solid var(--accent-green);">
            <div class="card-header">
                <div class="card-title" style="color: #34d399;">
                    <span>&bull;</span> API v2: Hardened API-ACE Endpoint
                </div>
                <span class="badge" style="background:#064e3b; color:#6ee7b7;">Hardened (L1-L7)</span>
            </div>
            <div class="controls-row">
                <label class="switch-label">
                    <input type="checkbox" id="chk-objcheck" checked onchange="updateConfig()">
                    <span>L3 Object Check</span>
                </label>
                <label class="switch-label">
                    <input type="checkbox" id="chk-ratelimit" checked onchange="updateConfig()">
                    <span>L5 Rate Limit & Lockout</span>
                </label>
                <button class="btn btn-gray btn-sm" onclick="resetDefense()">Reset Defense State</button>
            </div>
            <div class="btn-group">
                <button class="btn btn-danger" onclick="runV2Anonymous()">1. Anonymous Attack (No Token)</button>
                <button class="btn btn-danger" onclick="runV2BolaAttack()">2. BOLA Attack (Cross-Account)</button>
                <button class="btn btn-green" onclick="runV2LegitOwner()">3. Legitimate Owner (Masked)</button>
                <button class="btn btn-blue" onclick="runV2StaffAccess()">4. Staff Role (agent:read)</button>
            </div>
            <div class="mono-box" id="v2-response">// Results will appear here...</div>
        </div>

    </div>

    <!-- Structured L7 Audit Log Stream -->
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span>&bull;</span> L7 Structured Security Audit Logs
            </div>
            <button class="btn btn-gray btn-sm" onclick="fetchLogs()">Refresh Logs</button>
        </div>
        <div style="max-height: 280px; overflow-y: auto;">
            <table class="log-table">
                <thead>
                    <tr>
                        <th style="width: 140px;">Timestamp</th>
                        <th style="width: 60px;">Method</th>
                        <th style="width: 180px;">Endpoint</th>
                        <th style="width: 70px;">Status</th>
                        <th style="width: 140px;">Caller Sub</th>
                        <th>Security Audit Note</th>
                    </tr>
                </thead>
                <tbody id="log-tbody">
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 16px;">Loading logs...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let sampleData = null;

        async function init() {
            const res = await fetch('/api/customers/sample');
            sampleData = await res.json();
            fetchLogs();
        }

        async function runV1Test(id) {
            const el = document.getElementById('v1-response');
            el.innerText = `Fetching /api/v1/customers/${id}...`;
            const res = await fetch(`/api/v1/customers/${id}`);
            const data = await res.json();
            el.innerHTML = `<span class="status-badge status-${res.status}">${res.status} OK</span> (LEAK DETECTED: Full unmasked PII returned!)\\n\\n` + JSON.stringify(data, null, 2);
            fetchLogs();
        }

        async function runV1Scrape(count) {
            const el = document.getElementById('v1-response');
            el.innerText = `Simulating Optus sequential scrape of ${count} records...\\n`;
            for (let i = 1; i <= count; i++) {
                const res = await fetch(`/api/v1/customers/${i}`);
                const data = await res.json();
                el.innerText += `Record #${i}: ID=${data.id}, Name=${data.name}, Doc=${data.id_doc}, Phone=${data.phone}\\n`;
            }
            fetchLogs();
        }

        async function runV2Anonymous() {
            const el = document.getElementById('v2-response');
            const targetUuid = sampleData.customer_1.uuid;
            el.innerText = `Calling /api/v2/customers/${targetUuid} with NO Authorization header...`;
            const res = await fetch(`/api/v2/customers/${targetUuid}`);
            const data = await res.json();
            el.innerHTML = `<span class="status-badge status-${res.status}">${res.status}</span> (L2 REJECTED: Edge gateway blocked unauthenticated access)\\n\\n` + JSON.stringify(data, null, 2);
            fetchLogs();
        }

        async function runV2BolaAttack() {
            const el = document.getElementById('v2-response');
            // Customer 1 attempts to access Customer 2's UUID
            const attackerUuid = sampleData.customer_1.uuid;
            const victimUuid = sampleData.customer_2.uuid;

            el.innerText = `1. Generating valid token for Attacker (${attackerUuid.substring(0,8)}...)\\n2. Attempting to fetch Victim (${victimUuid.substring(0,8)}...)\\n`;
            
            const tokRes = await fetch('/api/auth/token', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({sub: attackerUuid, scope: 'self'})
            });
            const tokData = await tokRes.json();

            const res = await fetch(`/api/v2/customers/${victimUuid}`, {
                headers: {'Authorization': `Bearer ${tokData.token}`}
            });
            const data = await res.json();
            const badgeClass = res.status === 403 ? 'status-403' : 'status-429';
            el.innerHTML = `<span class="status-badge ${badgeClass}">${res.status}</span> (L3 BOLA DEFENSE TRIGGERED: Caller token sub != requested object UUID)\\n\\n` + JSON.stringify(data, null, 2);
            fetchLogs();
        }

        async function runV2LegitOwner() {
            const el = document.getElementById('v2-response');
            const ownerUuid = sampleData.customer_1.uuid;

            const tokRes = await fetch('/api/auth/token', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({sub: ownerUuid, scope: 'self'})
            });
            const tokData = await tokRes.json();

            const res = await fetch(`/api/v2/customers/${ownerUuid}`, {
                headers: {'Authorization': `Bearer ${tokData.token}`}
            });
            const data = await res.json();
            el.innerHTML = `<span class="status-badge status-200">200 OK</span> (AUTHORIZED: L6 data minimisation applied, sensitive fields masked)\\n\\n` + JSON.stringify(data, null, 2);
            fetchLogs();
        }

        async function runV2StaffAccess() {
            const el = document.getElementById('v2-response');
            const targetUuid = sampleData.customer_2.uuid;

            // Staff token with agent:read scope
            const tokRes = await fetch('/api/auth/token', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({sub: 'staff-analyst-uuid-999', scope: 'agent:read'})
            });
            const tokData = await tokRes.json();

            const res = await fetch(`/api/v2/customers/${targetUuid}`, {
                headers: {'Authorization': `Bearer ${tokData.token}`}
            });
            const data = await res.json();
            el.innerHTML = `<span class="status-badge status-200">200 OK</span> (AUTHORIZED: RBAC scope 'agent:read' permits staff lookup)\\n\\n` + JSON.stringify(data, null, 2);
            fetchLogs();
        }

        async function updateConfig() {
            const objcheck = document.getElementById('chk-objcheck').checked;
            const ratelimit = document.getElementById('chk-ratelimit').checked;
            await fetch('/api/v2/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({objcheck, ratelimit})
            });
            fetchLogs();
        }

        async function resetDefense() {
            await fetch('/api/v2/reset', {method: 'POST'});
            document.getElementById('v2-response').innerText = 'Defense counters & lockouts reset successfully.';
            fetchLogs();
        }

        async function fetchLogs() {
            const res = await fetch('/api/logs');
            const logs = await res.json();
            const tbody = document.getElementById('log-tbody');
            if (!logs.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 16px;">No security logs recorded yet.</td></tr>';
                return;
            }
            tbody.innerHTML = logs.slice(0, 15).map(l => `
                <tr>
                    <td>${l.timestamp}</td>
                    <td><strong>${l.method}</strong></td>
                    <td>${l.endpoint}</td>
                    <td><span class="status-badge status-${l.status}">${l.status}</span></td>
                    <td>${l.caller.length > 12 ? l.caller.substring(0, 12) + '...' : l.caller}</td>
                    <td>${l.note}</td>
                </tr>
            `).join('');
        }

        window.onload = init;
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    """Serves the interactive SOC dashboard & Attack Lab."""
    return render_template_string(DASHBOARD_HTML)

if __name__ == "__main__":
    print("=" * 60)
    print("API-ACE: Optus Breach Security Framework Backend")
    print("Serving on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)