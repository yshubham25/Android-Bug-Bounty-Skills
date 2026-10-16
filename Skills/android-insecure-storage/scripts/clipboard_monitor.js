// clipboard_monitor.js — Monitor clipboard for sensitive data
// Usage: frida -U -f com.target.app -l clipboard_monitor.js --no-pause
Java.perform(function() {
    var CM = Java.use("android.content.ClipboardManager");
    CM.setPrimaryClip.implementation = function(clip) {
        var item = clip.getItemAt(0);
        var text = item.getText() ? item.getText().toString() : "";
        console.log("\n[CLIPBOARD] setPrimaryClip:");
        console.log("  Text: " + text.substring(0, 200));
        if (text.match(/password|token|otp|pin|secret|bearer|session/i)) {
            console.log("  [!!!] SENSITIVE DATA ON CLIPBOARD");
        }
        this.setPrimaryClip(clip);
    };
    console.log("[+] Clipboard monitor active");
});
