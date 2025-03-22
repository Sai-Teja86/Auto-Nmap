Sai-Tej86/Auto-Nmap – An Nmap script Automation Tool
--------------------------------------------------------------------------
You can Automate multiple Nmap scripts by just entering which vulnerability you need to test on which target

Features

Multiple nmap scripts are available in built.

1. Open Ports & Services Enumeration
2. Unauthenticated Services Running
3. Misconfigured or Exposed Services
4. Firewall & IDS/IPS Detection & Bypass
5. ICMP Redirect Vulnerability
6. Weak or Default Credentials
7. Anonymous FTP Access
8. SMB Guest Access
9. RDP Authentication Weaknesses
10. SNMP Public/Private Community Strings
11. SMB Shares Enumeration
12. NFS Share Misconfigurations
13. DNS Zone Transfer Vulnerability
14. HTTP Banner Grabbing & Headers Leaks
15. SSL/TLS Certificate Expiry & Weak Ciphers
16. Outdated Apache, Nginx, or IIS Versions
17. Old OpenSSH Versions
18. Vulnerable MySQL/PostgreSQL Instances
19. SMBv1 (MS17-010 / EternalBlue)
20. SSL Heartbleed (CVE-2014-0160)
21. POODLE Attack (SSLv3)
22. DROWN Attack (SSL/TLS)
23. Logjam Attack (Weak DH Key Exchange)
24. FTP Bounce Attack
25. RDP Man-in-the-Middle Attack
26. HTTP Methods Misconfiguration
27. Directory Listing Enabled
28. HTTP Robots.txt Sensitive Entries
29. SQL Injection Detection
30. Cross-Site Scripting (XSS)
31. Open Redirect Vulnerability
32. Insecure Cookies & Session Handling
33. ARP Spoofing Detection
34. VLAN Hopping Vulnerability
35. Unpatched CVEs in Running Services
36. Weak Kerberos Authentication (MS14-068)
37. LLMNR/NBT-NS Poisoning Possibilities
38. BGP Route Hijacking Exposure
39. Windows XP/2003 Remote Code Execution
40. EternalBlue
41. Detects Weak SSL/TLS Configurations
42. Slowloris DoS Attack Vulnerability
43. Anonymous FTP Access Detection
44. Brute-Force MySQL Credentials
45. Detect SQL Injection Points
46. Weak RDP Encryption Detection
47. Scan Services for Known CVEs
48. HTTP Headers


Installation

git clone https://github.com/Sai-Teja86/Auto-Nmap.git
cd Auto-Nmap

Usage

1. python3 auto-nmap.py

2. You will find the below options

	📜 Select a target input method:
      		1. Single IP/Host	-	for single ip/host
		2. Target file		-	for multiple ip's. When prompted to enter the path of target file, just enter "targets.txt". You should priorly enter all ip's/hostsin the text file.

3. You will be prompted to choose an option from the lsit of vulnerabilities. Just enter the nuber and hit enter

4. After the scan is completed, you will be prompted to choose to continue or exit
     
	What would you like to do next?
      		1. Continue	-	To test for another vulnerability
   		2. Exit		-	To Exit
5. Once exit, you can find all the output in a file

	📝 Final results saved in 'nmap_scan_results.txt'
	👋 Exiting... Have a secure day!


**Note**

Make sure to clear or backup the output file 'nmap_scan_results.txt' to avaoid confusion, as the previous output will also be present in the same file.
   
   
