# Android Data Storage Locations Reference

## Internal Storage
```
/data/data/<package>/
├── shared_prefs/        # SharedPreferences XML files
├── databases/           # SQLite databases (.db)
├── files/               # App files (FileOutputStream)
├── cache/               # Cached data
├── app_webview/         # WebView data, cookies
│   ├── Cookies          # WebView cookie SQLite DB
│   └── Local Storage/   # DOM localStorage
├── code_cache/          # Compiled code cache
└── no_backup/           # Files excluded from backup
```

## External Storage (world-readable)
```
/sdcard/Android/data/<package>/
/sdcard/Android/obb/<package>/
/sdcard/<app-created-dirs>/
```

## Extraction Commands
```bash
# SharedPreferences (rooted)
adb shell su -c "cat /data/data/<pkg>/shared_prefs/*.xml"

# SQLite (rooted)
adb shell su -c "cp /data/data/<pkg>/databases/*.db /sdcard/"
adb pull /sdcard/*.db

# Backup (no root needed if allowBackup=true)
adb backup -f backup.ab -apk <pkg>

# Logcat
adb logcat --pid=$(adb shell pidof <pkg>)

# External storage
adb shell ls -laR /sdcard/Android/data/<pkg>/

# Objection
objection -g <pkg> explore
env
file download shared_prefs/auth.xml
sqlite connect databases/app.db
```
