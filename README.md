You can Automate multiple Nmap scripts by just entering which vulnerability you need to test on which target

Steps to use auto-nmap
1. python3 auto-nmap.py
2. You will find the below options
  📜 Select a target input method:
      1. Single IP/Host    -  for single ip/host
      2. Target file       -  for multiple ip's. When prompted to enter the path of target file, just enter "targets.txt". You should priorly enter all ip's/hostsin the text file.
3. You will be prompted to choose an option from the lsit of vulnerabilities. Just enter the nuber and hit enter
4. After the scan is completed, you will be prompted to choose to continue or exit
     What would you like to do next?
      1. Continue        -  To test for another vulnerability
      2. Exit            -  To Exit
5. Once exit, you can find all the output in a file
      📝 Final results saved in 'nmap_scan_results.txt'
      👋 Exiting... Have a secure day!


**Note**
Make sure to clear or backup the output file 'nmap_scan_results.txt' to avaoid confusion, as the previous output will also be present in the same file.
   
   
