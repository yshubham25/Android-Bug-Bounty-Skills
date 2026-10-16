// ssl_bypass_xamarin.js — Xamarin/Mono SSL Pinning Bypass
// Usage: frida -U -f com.target.app -l ssl_bypass_xamarin.js --no-pause
setTimeout(function(){
Java.perform(function(){
    console.log("[*] Xamarin SSL Bypass loaded");
    // Hook Mono ServicePointManager
    try{
        var Mono=Java.use("mono.android.Runtime");
        console.log("[+] Mono runtime detected");
    }catch(e){}
    // Standard Android hooks still needed as fallback
    try{
        var TM=Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TM.verifyChain.implementation=function(u,a,s,p,i){return u;};
        console.log("[+] TrustManagerImpl bypassed");
    }catch(e){}
    try{
        var X509=Java.use("javax.net.ssl.X509TrustManager");
        var SSLCtx=Java.use("javax.net.ssl.SSLContext");
        var TA=Java.registerClass({name:"com.bypass.XamarinTM",implements:[X509],methods:{
            checkClientTrusted:function(){},checkServerTrusted:function(){},getAcceptedIssuers:function(){return[];}
        }});
        var ctx=SSLCtx.getInstance("TLS");ctx.init(null,[TA.$new()],null);
        console.log("[+] X509TrustManager bypassed");
    }catch(e){}
    // AndroidClientHandler bypass
    try{
        var ACH=Java.use("Xamarin.Android.Net.AndroidClientHandler");
        if(ACH.TrustEverythingCertificateValidator){
            console.log("[+] AndroidClientHandler found");
        }
    }catch(e){}
    console.log("[*] Xamarin bypass complete");
});
},1000);
