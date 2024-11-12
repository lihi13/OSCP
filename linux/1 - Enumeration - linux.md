
- Username and hostname 
- Group memberships of the current user 
- Existing users and groups 
- Operating system, version and architecture 
- Running processes
- Network information 
- Schedule Task 
- Installed applications 
- collect passwords
- unmount 
- device drivers and kernel modules
- run as owner
- Automated Enumeration

after we get access on a machine we need to run the following commands to gather information

#### Username and hostname 

to get the user id:
```
id
```

Enterprises often enforce a naming convention scheme for hostnames, so they can be categorized by location, description, operating system, and service level.
```
hostname
```


#### Group memberships of the current user  and Existing users and groups 

To enumerate all users:
```
cat /etc/passwd
```

Login Name:encrypted hash:UID:GID:Comment:Home Folder: Login Shell

UID:GID that are zero is root user

shadow file
```
cat /etc/shadow
```
#### Operating system, version and architecture 

files that contain information about the operating system release and version:

```
cat /etc/issue
```

```
cat /etc/os-release
```

outputs the kernel version and architecture:
```
uname -a
```

outputs the kernel version:
```
uname -r
```

architectura:
```
arch
```
#### Running processes

list system processes (including those run by privileged users):
```
ps aux

ps aux --forest | grep '<command>'
```
processes running as root that are worth researching for possible vulnerabilities

#### Services

Services footprint
```
watch -n 1 "ps -aux | grep pass"

sudo tcpdump -i lo -A | grep "pass"
```

list writable services
```
find / -writable -name "*.service" 2>/dev/null
```

#### interesting files

```
/etc/profile.d

/home/<username>/.scripts

/var/backups
```

look for writable directory
```
find / -type d -maxdepth 5 -writable 2>/dev/null
```
#### Network information 

list the TCP/IP configuration of every network adapter:
```
ip a
ifconfig
```

network routing tables:
```
route 
routel
```

display active network connections and listening ports:
this can give us information about what running on the machine. port 80 of 443 for web server, 3306 for MYSQL server and more...
```
netstat -anp
ss -anp
netstat -tlpn
```

list hosts file and some more
```
cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null
```

active ports:
```
(netstat -punta || ss -nltpu || netstat -anv) | grep -i listen
```

list firewall rules (need root):
```
iptables
```

iptables-persistent package on Debian Linux saves firewall rules in specific files under **/etc/iptables** by default. These files are used by the system to restore netfilter rules at boot time. These files are often left with weak permissions, allowing them to be read by any local user on the target system.
_iptables-save_ command, dump the firewall configuration to a file specified by the user. This file is then usually used as input for the _iptables-restore_ command and used to restore the firewall rules at boot time.
If a system administrator had ever run this command, we could search the configuration directory (**/etc**) or grep the file system for iptables commands to locate the file. If the file has insecure permissions, we could use the contents to infer the firewall configuration rules running on the system.
```
cat /etc/iptables/rules.v4
```


#### Cron jobs 

Linux-based job scheduler is known as cron, the tasks split by the time they running (daily, weekly, ...)
```
ls -lah /etc/cron*
```

To view the current user's scheduled jobs
```
crontab -l
```

To reveals jobs run by the _root_ user
```
sudo crontab -l
```

see jobs in log file, it's revile the premisstion that the job run with
```
grep "CRON" /var/log/syslog
```

#### Installed applications 

install applications
```
system_profiler SPApplicationsDataType
```

Linux-based systems use a variety of package managers
to each linux distribution has it's own package manager, to list the installed application:

kali:
```
apt list
```

debian:
```
dkpg -l
```

and so on..

#### collect passwords

Sensitive files that are readable by an unprivileged user may also contain important information such as hard-coded credentials for a database or a service account running with higher privileges.

1. search in the file system
search the whole root directory (**/**) and use the **-writable** argument to specify the attribute we are interested in. We can also use **-type d** to locate directories, and filter errors with **2>/dev/null**:
```
find / -writable -type d 2>/dev/null
```

2. another place that people save clear passwords is in the env file, for bash in .bashrc file
to see env:
```
env
printenv
```

see .bashrc file
```
cat ~/.bashrc
```

3. if we found a password, we can try to create versions of her and brute force another users:
create a generated custom wordlist
```
crunch 6 6 -t Lab%%% > wordlist
```

then we can use hydra for example to brute force
```
hydra -l <user_name> -P <wordlist>  <target_IP> -t 4 <protocol> -V
```

4. to check privilege:
```
sudo -l
```

5. search in System  daemons services:
list information about higher-privilege processes such as the ones running inside the _root_ user context.
snapshot every second the ps command and search "pass" word
```
watch -n 1 "ps -aux | grep pass"
```
and maybe we will see credentials there

6. sometime IT account have permission to run tcpdump as unprivileged user, tcpdump dump network traffic

Let's try to capture traffic in and out of the loopback interface, then dump its content in ASCII using the **-A** parameter. Ultimately, we want to filter any traffic containing the "pass" keyword.
```
sudo tcpdump -i lo -A | grep "pass"
```
#### unmount
unmounted drives could contain valuable information

lists all drives that will be mounted at boot time:
```
cat /etc/fstab
```

list all mounted filesystems:
```
mount
```

to view all available disks:
```
lsblk
```
We'll notice that the _sda_ drive consists of three different numbered partitions. In some situations, showing information for all local disks on the system might reveal partitions that are not mounted. Depending on the system configuration (or misconfiguration), we then might be able to mount those partitions and search for interesting documents, credentials, or other information that could allow us to escalate our privileges or get a better foothold in the network.


#### device drivers and kernel modules

list loaded kernel modules:
```
lsmod
```

to find out more about the specific module:
```
/sbin/modinfo module_name
```
Once we've obtained a list of drivers and their versions, we are better positioned to find any relevant exploits.


##### run as owner

When running an executable, it normally inherits the permissions of the user that runs it. However, if the SUID permissions are set, the binary will run with the permissions of the file owner. This means that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.

When a user or a system-automated script launches a SUID application, it inherits the UID/GID of its initiating script: this is known as effective UID/GID (eUID, eGID), which is the actual user that the OS verifies to grant permissions for a given action.

Any user who manages to subvert a setuid root program to call a command of their choice can effectively impersonate the root user and gains all rights on the system. Penetration testers regularly search for these types of files when they gain access to a system as a way of escalating their privileges.

We can use **find** to search for SUID-marked binaries. In this case, we are starting our search at the root directory (**/**), searching for files (**-type f**) with the SUID bit set, (**-perm -u=s**) and discarding all error messages (**2>/dev/null**):
```
find / -perm -u=s -type f 2>/dev/null
```

**chmod u+s** ~filename~ command sets the effective UID of the running process to the executable owner's user ID - in this case root's.

enumerate our target system for binaries with capabilities
Capabilities: split all the possible privileged kernel calls up into groups of related functionality, then we can assign processes only to the subset they need. So the kernel calls were split up into a few dozen different categories, largely successfully.
```
/usr/sbin/getcap -r / 2>/dev/null
```

we can check in _GTFOBins_[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/insecure-system-components/abusing-setuid-binaries-and-capabilities#fn3) for ways to abuses it 


#### Automated Enumeration

- linpeas
- unix-privesc-check
- linenum
