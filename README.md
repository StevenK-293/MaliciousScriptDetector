# MaliciousScriptDetector

**Protects you from malicious scripts that attempt to steal IPs, or send data to webhooks. This script automatically detects and blocks dangerous HTTP requests.**  

- W.I.P
---

## **Features**  
✅ **Detects and blocks:**  
- Webhooks (`discord.com/api/webhooks/`)  
- IP grabbers (`grabify`, `iplogger`, etc.)  
- Suspicious network requests (`syn.request`, `game:HttpGet`, etc.)  
- Obfuscated scripts attempting to send data  

✅ **Hooks key functions to prevent data leaks**  
✅ **Warns the user when a script is blocked**  

---

## **How It Works**  
1. **Scans `loadstring` scripts** before execution for any network-related functions.  
2. **Hooks major HTTP functions** like `syn.request`, `game:HttpGet`, and `HttpService:RequestAsync`.  
3. **Blocks any request** that matches suspicious patterns.  
4. **Logs a warning** in the console if a script is blocked.  

---

✅ Safe scripts will run normally.  
❌ Malicious scripts will be blocked, and a warning will be shown.  

---

## **📜 License**  
This script is open source and free to use.
