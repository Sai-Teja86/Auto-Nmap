import os
import nmap
import subprocess
import colorama
from colorama import init, Fore, Style


# Vulnerability Scan List
scan_options = {
    "1": ("Open Ports & Services Enumeration", "-p- -sV -O"),
    "2": ("Service Scan", "-p- -sC"),
    "3": ("Unauthenticated Services Running", "-sV --script=auth"),
    "4": ("HTTP Banner Grabbing & Headers Leaks", "--script=http-headers"),
    "5": ("SSL/TLS Certificate Expiry & Weak Ciphers", "--script=ssl-cert,ssl-enum-ciphers"),
    "6": ("Old OpenSSH Versions", "--script=ssh2-enum-algos"),
    "7": ("HTTP Methods Misconfiguration", "--script=http-methods"),
    "8": ("HTTP Headers Misconfiguration", "--script=http-headers"),
    "9": ("Detects Weak SSL/TLS Configurations", "--script=ssl-enum-ciphers"),
    "10": ("Directory Listing Enabled", "--script=http-enum"),
    "11": ("HTTP Robots.txt Sensitive Entries", "--script=http-robots.txt"),
    "12": ("Unpatched CVEs in Running Services", "--script=vulners"),
    "13": ("Slowloris DoS Attack Vulnerability", "--script=http-slowloris"),
    "14": ("Outdated Apache, Nginx, or IIS Versions", "--script=http-server-header"),
    "15": ("Weak or Default Credentials", "-sU -sS --script=brute,smb-brute.nse"),
    "16": ("SQL Injection Detection", "--script=http-sql-injection"),
    "17": ("Cross-Site Scripting (XSS)", "--script=http-stored-xss"),
    "18": ("Open Redirect Vulnerability", "--script=http-open-redirect"),
    "19": ("Insecure Cookies & Session Handling", "--script=http-cookie-flags"),
    "20": ("Anonymous FTP Access Detection", "--script=ftp-anon"),
    "21": ("Misconfigured or Exposed Services", "-sV --script=misconfig,default,vuln -p-"),
    "22": ("Firewall & IDS/IPS Detection & Bypass", "-sA --script=firewalk -sS -D RND:10 firewall-bypass --script-args firewall-bypass.helper=\\\"ftp\\\""),
    "23": ("IP Forwarding", "-sn --script=ip-forwarding"),
    "24": ("Anonymous FTP Access", "--script=ftp-anon"),
    "25": ("SMB Guest Access", "--script=smb-enum-shares"),
    "26": ("RDP Authentication Weaknesses", "--script=rdp-ntlm-info"),
    "27": ("SNMP Public/Private Community Strings", "--script=snmp-brute"),
    "28": ("SMB Shares Enumeration", "--script=smb-enum-shares"),
    "29": ("NFS Share Misconfigurations", "--script=nfs-ls,nfs-statfs,nfs-showmount"),
    "30": ("DNS Zone Transfer Vulnerability", "-p 53 --script=dns-zone-transfer"), 
    "31": ("Vulnerable MySQL/PostgreSQL Instances", "--script=mysql-audit,pgsql-brute"),
    "32": ("SMBv1 (MS17-010 / EternalBlue)", "--script=smb-vuln-ms17-010"),
    "33": ("SSL Heartbleed (CVE-2014-0160)", "--script=ssl-heartbleed"),
    "34": ("POODLE Attack (SSLv3)", "--script=ssl-poodle"),
    "35": ("DROWN Attack (SSL/TLS)", "--script=ssl-drown"),
    "36": ("Logjam Attack (Weak DH Key Exchange)", "--script=ssl-dh-params"),
    "37": ("FTP Bounce Attack", "--script=ftp-bounce"),
    "38": ("RDP Man-in-the-Middle Attack", "--script=rdp-vuln-ms12-020"), 
    "39": ("ARP Spoofing Detection", "--script=arp-spoof"), 
    "40": ("Weak Kerberos Authentication (MS14-068)", "--script=krb5-enum-users"),
    "41": ("LLMNR/NBT-NS Poisoning Possibilities", "--script=smb-os-discovery"),
    "42": ("BGP Route Hijacking Exposure", "--script=bgp-open"),
    "43": ("Windows XP/2003 Remote Code Execution", "--script=smb-vuln-ms08-067"),
    "44": ("EternalBlue", "--script=smb-vuln-ms17-010"), 
    "45": ("Brute-Force MySQL Credentials", "--script=mysql-brute"),
    "46": ("Weak RDP Encryption Detection", "--script=rdp-vuln-ms12-020"),
    "47": ("SMB Shares Enumeration", "--script=smb-enum-shares"),
    "48": ("All Scripts Combined", "--script=http-headers,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,http-methods,http-enum,http-robots.txt,vulners,http-slowloris,http-server-header,brute,smb-brute.nse,http-sql-injection,http-stored-xss,http-open-redirect,http-cookie-flags,ftp-anon,misconfig,default,vuln,firewalk,ip-forwarding,smb-enum-shares,rdp-ntlm-info,snmp-brute,nfs-ls,nfs-statfs,nfs-showmount,dns-zone-transfer,mysql-audit,pgsql-brute,smb-vuln-ms17-010,ssl-heartbleed,ssl-poodle,ssl-drown,ssl-dh-params,ftp-bounce,rdp-vuln-ms12-020,arp-spoof,krb5-enum-users,smb-os-discovery,bgp-open,smb-vuln-ms08-067,mysql-brute,auth")
}

# Function to display the vulnerability list
def display_menu():
    print(Fore.YELLOW + "\nHere’s a list of vulnerabilities you can find using Nmap:\n")
    items = list(scan_options.items())
    mid = (len(items) + 1) // 2  # Split point
    left = items[:mid]
    right = items[mid:]
    for i in range(mid):
        left_item = left[i]
        right_item = right[i] if i < len(right) else ("", ("", ""))
        left_text = f"{left_item[0]}. {left_item[1][0]}"
        right_text = f"{right_item[0]}. {right_item[1][0]}" if right_item[0] else ""
        print(Fore.GREEN + f"{left_text:<50} {right_text}")
    print(Fore.RED + "\n0. Exit")

# Function to run the selected scan
def run_scan(scan_choice, target_file, output_file):
    scanner = nmap.PortScanner()
    
    # Get Nmap arguments
    scan_name, scan_args = scan_options[scan_choice]
    
    with open(target_file, "r") as file:
        targets = [line.strip() for line in file]

    print(Fore.CYAN + f"\n🔍 Running scan: {scan_name} on targets from {target_file}...")

    with open(output_file, "a") as out:
        out.write(f"\n### {scan_name} Results ###\n")

        for target in targets:
            print(f"Scanning {target}...")
            command = f"nmap {scan_args} {target}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            out.write(f"\n{command}\n{target}:\n{result.stdout}\n")


    print(Fore.GREEN + f"\n✅ Scan completed! Results saved in '{output_file}'\n")

# Post-scan menu function
def post_scan_menu():
    while True:
        print(Fore.CYAN + "\n📜 Select an option:")
        print("1. Continue")
        print("2. Exit")
        choice = input(Fore.GREEN + "Enter your choice: " + Fore.RESET).strip()

        if choice == "1":
            return  # Redisplay the menu
        elif choice == "2":
            print(Fore.RED + "🚪 Exiting program...")
            exit()
        else:
            print(Fore.RED + "❌ Invalid choice! Please enter 1 or 2.")
            
# Target selection function
def get_targets():
    while True:
        print(Fore.CYAN + "\n📜 Select a target input method:")
        print("1. Single IP/Host")
        print("2. Target file")
        choice = input(Fore.GREEN + "Enter your choice (1/2): " + Fore.RESET).strip()
        
        if choice == "1":
            target = input(Fore.MAGENTA + "\n🔹 Enter the IP or hostname to scan: ")
            filename = "single_target.txt"
            with open(filename, "w") as file:
                file.write(target + "\n")
            return filename 
        elif choice == "2":
            file_path = input(Fore.MAGENTA + "\n📂 Enter the path to your target file (e.g., targets.txt): ")
            if not os.path.exists(file_path):
                print(Fore.RED + "❌ File not found! Try again.")
                continue
            return file_path
        else:
            print(Fore.RED + "❌ Invalid choice! Please enter 1 or 2.")
            
# Main function
def main():
    print(Fore.CYAN + Style.BRIGHT + "\n🔎 Welcome to the Nmap Vulnerability Scanner!")
    
    target_file = get_targets()
    output_file = "nmap_scan_results.txt"
    
    while True:
        display_menu()
        scan_choice = input(Fore.GREEN +"\n💡 Select an option (or 0 to exit): ")

        if scan_choice == "0":
            print(Fore.MAGENTA + "\n📝 Final results saved in 'nmap_scan_results.txt'")
            print(Fore.YELLOW + "👋 Exiting... Have a secure day!")
            break
        elif scan_choice in scan_options:
            run_scan(scan_choice, target_file, output_file)
            
            # Small menu after scan completion
            while True:
                print(Fore.CYAN + "\nWhat would you like to do next?")
                print(Fore.YELLOW + "1. Continue")
                print(Fore.RED + "2. Exit")
                
                choice = input(Fore.GREEN + "\nEnter your choice (1/2): ")

                if choice == "1":
                    break  # Continue to next scan
                elif choice == "2":
                    print(Fore.MAGENTA + "\n📝 Final results saved in 'nmap_scan_results.txt'")
                    print(Fore.YELLOW + "👋 Exiting... Have a secure day!")
                    return  # Exit the program
                else:
                    print(Fore.RED + "❌ Invalid choice! Please enter 1 or 2.")

        else:
            print("❌ Invalid choice! Please select a valid option.")

if __name__ == "__main__":
    main()

