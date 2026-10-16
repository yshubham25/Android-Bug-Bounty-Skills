# Burp Suite Dynamic Testing Methodology for Android

What to do AFTER you bypass SSL pinning and can see API traffic.
This bridges your static skills to dynamic bounty-paying findings.

## Setup

1. SSL pinning bypassed (use your `android-network-security` skill)
2. Burp proxy intercepting all HTTPS traffic
3. Logged in with a test account
4. Second test account ready for cross-account testing

## Step 1 — Map the API surface (passive)

Browse every feature in the app with Burp Proxy on. Don't test yet, just collect.

```
Target → Site map → filter by target domain
Capture: every endpoint, method, parameter, header, auth token
```

What to record for each endpoint:
- URL path and HTTP method
- Auth header format (Bearer, Cookie, custom)
- Request body structure (JSON fields, IDs)
- Response fields (what data comes back)
- Any ID parameters (user_id, order_id, conversation_id)

## Step 2 — IDOR / BOLA testing (highest bounty)

The #1 highest-paying mobile bug class.

```
For every endpoint with an ID parameter:
1. Log in as Account A
2. Capture a request containing Account A's resource ID
3. Replace the ID with Account B's resource ID
4. Send → does the server return Account B's data?

Common IDOR locations:
- /api/user/{user_id}/profile
- /api/orders/{order_id}
- /api/messages/{conversation_id}
- /api/documents/{doc_id}/download
- Any numeric or UUID parameter
```

**Burp tool:** Install Autorize extension. It automatically replays
every request with a lower-privileged session to test access control.

**Severity:** Usually High-Critical if private data is returned.

## Step 3 — Authentication testing

```
- Remove Authorization header entirely → does endpoint still work?
- Use expired token → does server reject it?
- Use Account A's token on Account B's endpoints
- Modify JWT claims (if JWT): change user_id, role, is_admin
- Test token after password change → is old token revoked?
- Test refresh token → can it be replayed indefinitely?
```

## Step 4 — Rate limiting

```
- Login endpoint: send 100 rapid requests with wrong password
  → Does it lock out? After how many attempts?
- OTP endpoint: brute-force 4-digit OTP (0000-9999)
  → Does it rate-limit? Can you bypass with different headers?
- Password reset: request 50 reset emails rapidly
  → Does it throttle?

Burp tool: Intruder → Sniper → payload list of passwords/OTPs
```

## Step 5 — Race conditions

```
Send the same request simultaneously to exploit TOCTOU bugs:

- Apply coupon/promo code: send 10 requests at once
  → Does it apply the discount multiple times?
- Transfer money: send same transfer 10x simultaneously
  → Does it debit once but credit multiple times?
- Redeem reward: parallel requests to redeem same reward
  → Double-spend?

Burp tool: Turbo Intruder or Repeater → Send group in parallel
```

**Key technique:** Use Burp's "Send group in parallel (last-byte sync)"
for precise race condition testing. Standard Intruder is too slow.

## Step 6 — Input validation

```
For every parameter the app sends:
- SQL injection: ' OR 1=1-- in string fields
- NoSQL injection: {"$gt":""} in JSON fields  
- Command injection: ;id; or |id| in string fields
- Path traversal: ../../etc/passwd in file parameters
- SSRF: http://169.254.169.254/ in URL parameters
- XSS: <script>alert(1)</script> in fields that render in WebView
```

## Step 7 — Business logic

```
- Change price/quantity in client request → does server validate?
- Skip steps in multi-step flow → does server enforce order?
- Apply referral code to own account
- Transfer negative amount (credit instead of debit)
- Change currency but keep amount
- Downgrade plan → does server remove premium features?
- Delete account → is data actually purged?
```

## Step 8 — Mass assignment

```
Add extra fields to requests that the app doesn't normally send:

POST /api/user/update
Original: {"name": "test"}
Modified: {"name": "test", "role": "admin", "is_verified": true}

→ Does the server accept and apply the extra fields?
```

## Report format for dynamic findings

```
Title: IDOR in /api/orders/{id} Allows Access to Other Users' Orders
CWE: CWE-639
Severity: High

Steps:
1. Login as Account A, note order ID 12345
2. Login as Account B, capture auth token
3. Send: GET /api/orders/12345 with Account B's token
4. Response contains Account A's order details

Impact: Any authenticated user can access any order.
```

## Burp extensions to install

| Extension | Purpose |
|-----------|---------|
| Autorize | Automatic IDOR/access control testing |
| Turbo Intruder | Race condition testing |
| JSON Beautifier | Readable API responses |
| JWT Editor | Decode/modify JWT tokens |
| Param Miner | Find hidden parameters |
| Logger++ | Advanced request logging |
| Active Scan++ | Enhanced active scanning |
