# Authentication Bypass Methodology

## Phase 1: Map the Auth Surface
1. Parse AndroidManifest.xml for exported components
2. Identify auth-related classes (AuthManager, SessionManager, etc.)
3. Find auth state storage (SharedPreferences, SQLite, files)
4. Map login → dashboard flow in code

## Phase 2: Identify Bypass Paths
1. Can protected activities be launched directly?
2. Can deep links skip auth checks?
3. Are auth flags stored client-side?
4. Does biometric use CryptoObject?
5. Is PIN/OTP verified server-side?
6. Are intent extras trusted for auth decisions?

## Phase 3: Validate
1. ADB: launch exported activities without login
2. Deep links: navigate to protected screens
3. Frida: hook SharedPreferences, BiometricPrompt
4. Burp: verify if backend enforces auth independently

## Phase 4: Classify Impact
- UI-only bypass (no data) → Medium
- Data access without auth → High-Critical
- Action execution (payment, settings) → Critical
- Token/credential theft → Critical

## Key Principle
A UI-only bypass is NOT full account compromise.
Always verify: does the backend also skip authentication?
