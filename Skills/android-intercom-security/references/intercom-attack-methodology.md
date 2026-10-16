# Intercom Attack Methodology

## What is Intercom identity verification?
Intercom supports HMAC-based identity verification where the server
generates user_hash = HMAC-SHA256(identity_secret, user_id_or_email)
and passes it to the client SDK. Intercom's server validates the hash
before associating the messenger session with the user.

When disabled, any caller with the App ID and SDK credential can claim
to be any user by supplying their email or userId.

## Attack surface
1. SDK credentials in APK (App ID + android_sdk-XXX)
2. Identity verification status (enabled/disabled)
3. Conversation API endpoints (/messenger/mobile/conversations/*)
4. Cross-account conversation access (IDOR/BOLA)
5. Identity impersonation (claim arbitrary email/userId)
6. Conversation creation as arbitrary user

## What is NOT a vulnerability
- SDK credentials in APK (expected, required for client SDK)
- Missing user_hash reference (may be handled server-side)
- Creating a visitor/support conversation (may be intentional)
- Accessing your own conversations with valid credentials

## What IS a vulnerability
- Reading another authenticated user's private conversation
- Creating conversations that appear to come from another user
- Accessing conversation transcripts without valid identity proof
- Bypassing identity verification to impersonate users
