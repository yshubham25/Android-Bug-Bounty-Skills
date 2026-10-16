# Intercom Detection & Analysis Guide

## How to identify Intercom in an APK
1. Search for `io.intercom.android` package in decompiled source
2. Look for `mobile-messenger.intercom.com` API hostname
3. Find `android_sdk-` prefixed credential strings
4. Check for `Intercom.initialize` or `Intercom.client` calls

## Identity verification assessment
- user_hash + HMAC present → likely enabled (lower risk)
- loginIdentifiedUser WITHOUT user_hash → potentially disabled (test!)
- Only loginUnidentifiedUser → visitor-only (may be intentional)
- Cannot determine → requires runtime validation

## What is NOT a vulnerability
- SDK credentials in APK (required for client SDK to function)
- Missing user_hash reference alone (may be handled server-side)
- Creating visitor support conversations (usually intentional)

## What IS a vulnerability
- Cross-account conversation access (IDOR/BOLA)
- User impersonation via arbitrary email/userId
- Private message transcript exposure to unauthorized caller

## Testing requirements
- Two researcher-owned test accounts
- Burp Suite configured with SSL bypass
- Test markers in each account's Intercom conversations
- Clean sessions between cross-account tests
