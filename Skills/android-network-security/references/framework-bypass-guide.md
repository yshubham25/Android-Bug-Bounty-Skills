# SSL Pinning Bypass by Framework

## Native Java/Kotlin
Stack: OkHttp, HttpURLConnection, Volley, Retrofit (all use Java TLS layer)
Bypass: Objection, Frida universal, network_security_config patch, Magisk

## Flutter
Stack: BoringSSL compiled into libflutter.so (Dart networking on top)
Why different: Java hooks don't reach BoringSSL inside native binary
Bypass: kill_flutter (auto-offset), reFlutter (binary patch), manual Frida offset
Key files: libflutter.so (engine), libapp.so (app code)

## React Native
Stack: OkHttp on Android (fetch() bridges to native)
Bypass: Same as Java/Kotlin — Objection, Frida universal
Special: react-native-ssl-pinning uses OkHttp CertificatePinner

## Xamarin
Stack: Mono HttpClient / AndroidClientHandler / ModernHttpClient
Bypass: Frida Mono hooks, DLL patching via dnSpy
Key: assemblies/ folder contains .NET DLLs

## Cordova / Ionic
Stack: System WebView → Android network stack
Bypass: Network security config patch, Magisk system cert
Simplest: Just trust user certs via config patch

## Unity
Stack: IL2CPP or Mono backend, UnityWebRequest
Bypass: Frida IL2CPP hooks or Mono hooks depending on build
Key files: libil2cpp.so, libunity.so
