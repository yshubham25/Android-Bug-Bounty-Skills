# Firebase Security Rules Reference

## DANGEROUS (fully open)
```json
{"rules": {".read": true, ".write": true}}
```

## STILL DANGEROUS (any authenticated user)
```json
{"rules": {".read": "auth != null", ".write": "auth != null"}}
```

## SECURE (owner-only)
```json
{"rules": {"users": {"$uid": {".read": "$uid === auth.uid", ".write": "$uid === auth.uid"}}}}
```

## Firestore equivalent
```
match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```
