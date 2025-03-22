# 🚀 Auto-Nmap – An Nmap Script Automation Tool  

![GitHub stars](https://img.shields.io/github/stars/Sai-Tej86/Auto-Nmap?style=flat-square)  
![GitHub forks](https://img.shields.io/github/forks/Sai-Tej86/Auto-Nmap?style=flat-square)  
![GitHub license](https://img.shields.io/github/license/Sai-Tej86/Auto-Nmap?style=flat-square)  
![GitHub issues](https://img.shields.io/github/issues/Sai-Tej86/Auto-Nmap?style=flat-square)  

---

## 🎯 **About Auto-Nmap**
🔹 Automate multiple **Nmap scripts** effortlessly.  
🔹 Simply enter **which vulnerability** you need to test on **which target** – and let Auto-Nmap handle the rest!  

---

## 🚀 **Features**
✅ **Built-in multiple Nmap scripts** to scan for various security vulnerabilities:  

### 🔍 **Port & Service Enumeration**
- Open Ports & Services Enumeration  
- Unauthenticated Services Running  
- Misconfigured or Exposed Services  

### 🔥 **Exploitable Vulnerabilities**
- SMBv1 (MS17-010 / EternalBlue)  
- SSL Heartbleed (CVE-2014-0160)  
- POODLE Attack (SSLv3)  
- DROWN Attack (SSL/TLS)  
- Logjam Attack (Weak DH Key Exchange)  
- FTP Bounce Attack  
- RDP Man-in-the-Middle Attack  
- Windows XP/2003 Remote Code Execution  

### 🛡️ **Authentication & Access Issues**
- Weak or Default Credentials  
- Anonymous FTP Access  
- SMB Guest Access  
- RDP Authentication Weaknesses  
- SNMP Public/Private Community Strings  
- Weak Kerberos Authentication (MS14-068)  
- Brute-Force MySQL Credentials  

### 🔧 **Web Security Issues**
- HTTP Banner Grabbing & Headers Leaks  
- SSL/TLS Certificate Expiry & Weak Ciphers  
- HTTP Methods Misconfiguration  
- Directory Listing Enabled  
- SQL Injection Detection  
- Cross-Site Scripting (XSS)  
- Open Redirect Vulnerability  
- Insecure Cookies & Session Handling  

### ⚡ **Network & Protocol Exploits**
- Firewall & IDS/IPS Detection & Bypass  
- ARP Spoofing Detection  
- VLAN Hopping Vulnerability  
- BGP Route Hijacking Exposure  
- Detects Weak SSL/TLS Configurations  
- Slowloris DoS Attack Vulnerability  
- LLMNR/NBT-NS Poisoning Possibilities  

---

## 🛠️ **Installation**
```bash
git clone https://github.com/Sai-Tej86/Auto-Nmap.git
cd Auto-Nmap
```
## 📌 Usage
```bash
python3 auto-nmap.py
```
1️⃣ Select a target input method:

1 ➜ Single IP/Host

2 ➜ Target File (Enter "targets.txt" containing multiple hosts/IPs)

2️⃣ Choose a vulnerability to test – Just enter the number and hit enter.

3️⃣ After the scan completes, you will be prompted with:

    What would you like to do next?
    1. Continue  - To test for another vulnerability
    2. Exit      - To Exit

4️⃣ Once you exit, the final results will be saved in:

    📝 Final results saved in 'nmap_scan_results.txt'
    👋 Exiting... Have a secure day!

