import os
import nmap
import subprocess
import colorama
from colorama import init, Fore, Style


# Vulnerability Scan List
scan_options = {
    "1": ("Open Ports & Services Enumeration", "-p- -sV -O"),
    "2": ("Unauthenticated Services Running", "-sV --script=auth"),
    "3": ("Misconfigured or Exposed Services", "-sV --script=misconfig,default,vuln -p-"),
    "4": ("Firewall & IDS/IPS Detection & Bypass", "-sA --script=firewalk -sS -D RND:10 firewall-bypass --script-args firewall-bypass.helper=\\\"ftp\\\""),
    "5": ("ICMP Redirect Vulnerability", "--script=icmp-redirect"),
    "6": ("Weak or Default Credentials", "-sU -sS --script=brute,smb-brute.nse"),
    "7": ("Anonymous FTP Access", "--script=ftp-anon"),
    "8": ("SMB Guest Access", "--script=smb-enum-shares"),
    "9": ("RDP Authentication Weaknesses", "--script=rdp-ntlm-info"),
    "10": ("SNMP Public/Private Community Strings", "--script=snmp-brute"),
    "11": ("SMB Shares Enumeration", "--script=smb-enum-shares"),
    "12": ("NFS Share Misconfigurations", "--script=nfs-ls,nfs-statfs,nfs-showmount"),
    "13": ("DNS Zone Transfer Vulnerability", "-p 53 --script=dns-zone-transfer"),
    "14": ("HTTP Banner Grabbing & Headers Leaks", "--script=http-headers"),
    "15": ("SSL/TLS Certificate Expiry & Weak Ciphers", "--script=ssl-cert,ssl-enum-ciphers"),
    "16": ("Outdated Apache, Nginx, or IIS Versions", "--script=http-server-header"),
    "17": ("Old OpenSSH Versions", "--script=ssh2-enum-algos"),
    "18": ("Vulnerable MySQL/PostgreSQL Instances", "--script=mysql-audit,pgsql-brute"),
    "19": ("SMBv1 (MS17-010 / EternalBlue)", "--script=smb-vuln-ms17-010"),
    "20": ("SSL Heartbleed (CVE-2014-0160)", "--script=ssl-heartbleed"),
    "21": ("POODLE Attack (SSLv3)", "--script=ssl-poodle"),
    "22": ("DROWN Attack (SSL/TLS)", "--script=ssl-drown"),
    "23": ("Logjam Attack (Weak DH Key Exchange)", "--script=ssl-dh-params"),
    "24": ("FTP Bounce Attack", "--script=ftp-bounce"),
    "25": ("RDP Man-in-the-Middle Attack", "--script=rdp-vuln-ms12-020"),
    "26": ("HTTP Methods Misconfiguration", "--script=http-methods"),
    "27": ("Directory Listing Enabled", "--script=http-enum"),
    "28": ("HTTP Robots.txt Sensitive Entries", "--script=http-robots.txt"),
    "29": ("SQL Injection Detection", "--script=http-sql-injection"),
    "30": ("Cross-Site Scripting (XSS)", "--script=http-stored-xss"),
    "31": ("Open Redirect Vulnerability", "--script=http-open-redirect"),
    "32": ("Insecure Cookies & Session Handling", "--script=http-cookie-flags"),
    "33": ("ARP Spoofing Detection", "--script=arp-spoof"),
    "34": ("VLAN Hopping Vulnerability", "--script=vlan-hopping"),
    "35": ("Unpatched CVEs in Running Services", "--script=vulners"),
    "36": ("Weak Kerberos Authentication (MS14-068)", "--script=krb5-enum-users"),
    "37": ("LLMNR/NBT-NS Poisoning Possibilities", "--script=smb-os-discovery"),
    "38": ("BGP Route Hijacking Exposure", "--script=bgp-open"),
    "39": ("Windows XP/2003 Remote Code Execution", "--script=smb-vuln-ms08-067"),
    "40": ("EternalBlue", "--script=smb-vuln-ms17-010"),
    "41": ("Detects Weak SSL/TLS Configurations", "--script=ssl-enum-ciphers"),
    "42": ("Slowloris DoS Attack Vulnerability", "--script=http-slowloris"),
    "43": ("Anonymous FTP Access Detection", "--script=ftp-anon"),
    "44": ("Brute-Force MySQL Credentials", "--script=mysql-brute"),
    "45": ("Detect SQL Injection Points", "--script=http-sql-injection"),
    "46": ("Weak RDP Encryption Detection", "--script=rdp-vuln-ms12-020"),
    "47": ("Scan Services for Known CVEs", "--script=vulners")
}

# Function to display the vulnerability list
def display_menu():
    print(Fore.YELLOW + "\nHere’s a list of vulnerabilities you can find using Nmap:\n")
    for key, (desc, _) in scan_options.items():
        print(Fore.GREEN + f"{key}. {desc}")
    print(Fore.RED + "0. Exit")

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
            out.write(f"\n{target}:\n{result.stdout}\n")


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

