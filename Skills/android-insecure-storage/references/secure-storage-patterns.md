# Secure vs Insecure Storage Patterns

## SharedPreferences

### INSECURE
```java
SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
prefs.edit().putString("password", password).apply();
prefs.edit().putString("session_token", token).apply();
```

### SECURE — EncryptedSharedPreferences
```java
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
SharedPreferences prefs = EncryptedSharedPreferences.create(
    context, "auth", masterKey,
    PrefKeyEncryptionScheme.AES256_SIV,
    PrefValueEncryptionScheme.AES256_GCM);
prefs.edit().putString("session_token", token).apply();
```

## SQLite

### INSECURE
```java
SQLiteDatabase db = openOrCreateDatabase("users.db", MODE_PRIVATE, null);
db.execSQL("INSERT INTO users VALUES ('" + email + "', '" + password + "')");
```

### SECURE — SQLCipher
```java
SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(
    dbFile, "encryption_key_from_keystore", null);
```

## File Storage

### INSECURE — External storage
```java
File file = new File(Environment.getExternalStorageDirectory(), "creds.txt");
```

### SECURE — Internal encrypted
```java
File file = new File(context.getFilesDir(), "creds.enc");
// Encrypt before writing using Android Keystore key
```

## Backup

### INSECURE
```xml
<application android:allowBackup="true">
```

### SECURE
```xml
<application android:allowBackup="false">
<!-- OR use extraction rules -->
<application android:dataExtractionRules="@xml/data_extraction_rules">
```
