# API-ACE: API Access Control Enforcement Framework
### Case Study: The Optus Data Breach (2022)
**Course:** Cyber Security (Unit 4), Theory CA-2 Part 2 | B.Tech CSE  
**Group:** G26 (Anushka Tandon, Yagnita Patel, Laxmi Sah)  
**Institution:** Symbiosis Institute of Technology, Pune  

---

## 📌 Project Overview
This project implements and evaluates the **API-ACE (API Access Control Enforcement)** framework designed to prevent API-level data breaches, specifically addressing the access control failures identified in the **2022 Optus Data Breach** (OWASP API Top 10 risks: BOLA, Broken Authentication, Unrestricted Resource Consumption, and Excessive Data Exposure).

The system consists of:
1. **API v1 (Vulnerable API - Optus Style)**: Exposed customer endpoint with sequential integer IDs, no authentication, and unmasked data leakage.
2. **API v2 (Hardened API - API-ACE)**: 7-layer defense enforcing zero-trust access control, signed JWT tokens, object-level authorization, sliding-window rate limiting, lockout on enumeration, and data masking.
3. **`app.py`**: Live Flask backend with an interactive Cyber Security Web SOC & Attack Lab dashboard at `http://127.0.0.1:5000`.
4. **`optus_api_demo.py`**: Standalone evaluation and benchmarking suite reproducing experiments **E1 through E6** (Tables 13 & 14 in the CA-2 Report).

---

## 🛡️ The 7 Defense Layers of API-ACE
- **L1 - Inventory & Lifecycle:** Cataloging endpoints and decommissioning dormant APIs.
- **L2 - Edge Authentication:** Deny-by-default gateway validating signed short-lived PyJWT tokens (`HS256`, audience `customers-api`).
- **L3 - Object-Level & Function-Level Authorization:** ABAC owner check (`token sub == cust_uuid`) and RBAC scope check (`agent:read`). Uniform `403 Forbidden` response prevents identifier enumeration.
- **L4 - Opaque Identifiers:** Random UUIDv4 instead of sequential integer IDs.
- **L5 - Abuse Resistance:** Sliding-window rate limiter (60 req / 60s) + automatic client lockout after 5 denied requests (strikes $\ge$ 5).
- **L6 - Data Minimisation:** Masking identity documents (`*****871`) and stripping unneeded PII (`dob`, `phone`).
- **L7 - Assurance & Structured Logging:** Audit logging of every request with timestamp, IP, caller identity, and defense outcomes.

---

## 🚀 How to Run

### 1. Launch the Live Web App & Attack Lab
```powershell
py app.py
```
- Open your browser to **`http://127.0.0.1:5000`**
- Test attacks visually:
  - Enumerate vulnerable v1 endpoints (see raw PII leaked).
  - Attempt anonymous attack on v2 (L2 401 Unauthorized).
  - Attempt cross-customer BOLA attack on v2 (L3 403 Forbidden + L5 lockout trigger).
  - Perform legitimate owner access (200 OK with masked ID `*****871`).
  - Perform staff access using `agent:read` scope.
  - Inspect real-time L7 security audit logs.

### 2. Run the Benchmark & Reproduce CA-2 Report Results
```powershell
py optus_api_demo.py
```
Executes all six experimental scenarios across 10,000 synthetic records:
- **E1:** Anonymous sequential enumeration on v1 $\rightarrow$ 10,000 exposed (100% leak).
- **E2:** Anonymous attack on v2 $\rightarrow$ 60 $\times$ 401, then 9,940 $\times$ 429 (0 exposed).
- **E3-A:** Valid token, 9,999 victims with auth only $\rightarrow$ 9,999 $\times$ 200 (100% leak, proves auth alone does not stop BOLA).
- **E3-B:** Valid token with object check $\rightarrow$ 9,999 $\times$ 403 (0 exposed).
- **E3-C:** Valid token with full API-ACE $\rightarrow$ 5 $\times$ 403, then 9,994 $\times$ 429 (lockout after 5 strikes).
- **E4:** Legitimate owner read $\rightarrow$ 200 OK (masked ID document `*****871`).
- **E5:** Latency benchmark (3,000 requests per API).
- **E6 (A–D):** Distributed attack across 50 IP addresses comparing IP-keyed vs Token-keyed rate limiting.
