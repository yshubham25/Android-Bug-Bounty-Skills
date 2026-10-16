// ssl_bypass_universal.js — Universal Android SSL Pinning Bypass
// Covers: TrustManagerImpl, OkHttp3/4, Conscrypt, TrustKit, Volley,
//         HttpsURLConnection, WebViewClient, Flutter (partial), custom X509TM
// Usage: frida -U -f com.target.app -l ssl_bypass_universal.js --no-pause

setTimeout(function() {
Java.perform(function() {
    console.log("[*] Universal SSL Pinning Bypass loaded\n");
    var bypassed = [];

    // === 1. TrustManagerImpl (Android system) ===
    try {
        var TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TM.verifyChain.implementation = function(untrusted, authType, session, params, id) {
            console.log("[+] TrustManagerImpl.verifyChain bypassed");
            return untrusted;
        };
        bypassed.push("TrustManagerImpl");
    } catch(e) {}

    // === 2. Custom X509TrustManager — inject trust-all ===
    try {
        var X509TM = Java.use("javax.net.ssl.X509TrustManager");
        var SSLCtx = Java.use("javax.net.ssl.SSLContext");
        var TrustAll = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [X509TM],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; },
            }
        });
        var ctx = SSLCtx.getInstance("TLS");
        ctx.init(null, [TrustAll.$new()], null);
        SSLCtx.getInstance.overload("java.lang.String").implementation = function(type) {
            return ctx;
        };
        bypassed.push("X509TrustManager");
    } catch(e) {}

    // === 3. OkHttp3 CertificatePinner ===
    try {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
            console.log("[+] OkHttp3 CertificatePinner.check bypassed: " + host);
        };
        bypassed.push("OkHttp3");
    } catch(e) {}

    // OkHttp3 variant 2
    try {
        var CP2 = Java.use("okhttp3.CertificatePinner");
        CP2.check$okhttp.implementation = function(host, fn) {
            console.log("[+] OkHttp3 check$okhttp bypassed: " + host);
        };
        bypassed.push("OkHttp3-variant2");
    } catch(e) {}

    // === 4. OkHttp legacy (com.squareup) ===
    try {
        var SQ = Java.use("com.squareup.okhttp.CertificatePinner");
        SQ.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function(a, b) {};
        bypassed.push("OkHttp-squareup");
    } catch(e) {}

    // === 5. Conscrypt / BoringSSL ===
    try {
        var Conscrypt = Java.use("org.conscrypt.TrustManagerImpl");
        Conscrypt.verifyChain.implementation = function(untrusted, authType, session, params, id) {
            console.log("[+] Conscrypt.verifyChain bypassed");
            return untrusted;
        };
        bypassed.push("Conscrypt");
    } catch(e) {}

    // === 6. TrustKit ===
    try {
        var TK = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TK.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function(a, b) { return true; };
        bypassed.push("TrustKit");
    } catch(e) {}

    // === 7. HttpsURLConnection ===
    try {
        var HC = Java.use("javax.net.ssl.HttpsURLConnection");
        HC.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
        };
        HC.setSSLSocketFactory.implementation = function(factory) {
            console.log("[+] HttpsURLConnection.setSSLSocketFactory bypassed");
        };
        bypassed.push("HttpsURLConnection");
    } catch(e) {}

    // === 8. WebViewClient SSL error ===
    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebViewClient SSL error bypassed");
            handler.proceed();
        };
        bypassed.push("WebViewClient");
    } catch(e) {}

    // === 9. Apache HTTP (legacy) ===
    try {
        var AHV = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AHV.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function() {};
        bypassed.push("Apache-HTTP");
    } catch(e) {}

    // === 10. CWAC-Netsecurity ===
    try {
        var CWAC = Java.use("com.commonsware.cwac.netsecurity.TrustManagerBuilder");
        CWAC.withManifestConfig.implementation = function(ctx) { return this; };
        bypassed.push("CWAC-Netsecurity");
    } catch(e) {}

    // === 11. Appcelerator Titanium ===
    try {
        var APT = Java.use("appcelerator.https.PinningTrustManager");
        APT.checkServerTrusted.implementation = function(chain, authType) {};
        bypassed.push("Appcelerator");
    } catch(e) {}

    // === 12. Netty ===
    try {
        var Netty = Java.use("io.netty.handler.ssl.util.InsecureTrustManagerFactory");
        bypassed.push("Netty-available");
    } catch(e) {}

    // === Flutter native bypass (partial — for basic implementations) ===
    try {
        var m = Process.findModuleByName("libflutter.so");
        if (m) {
            console.log("[*] Flutter detected — use kill_flutter or reFlutter for full bypass");
            console.log("    libflutter.so base: " + m.base);
            bypassed.push("Flutter-detected");
        }
    } catch(e) {}

    console.log("\n[*] Bypassed " + bypassed.length + " implementations:");
    bypassed.forEach(function(b) { console.log("    ✓ " + b); });
    console.log("\n[*] Set device proxy to your Burp/mitmproxy and start testing\n");
});
}, 1000);
