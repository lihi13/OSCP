
- Username and hostname 
- Group memberships of the current user 
- Existing users and groups 
- Operating system, version and architecture 
- Network information 
- Installed applications 
- Running processes
- collect passwords
- history
- Automated Enumeration

after we get access on a machine we need to run the following commands to gather information

#### username and host name

```
whoami
whoami /priv
whoami /all
```

the hostname can get indication of the purpose and type of a machine
for example _WEB01_ for a web server or _MSSQL01_ for a _MSSQL_ server.
```
hostname
```

#### Group membership of the current user

my groups
```
whoami /groups
```

all groups 
```
net localgroup
net localgroup administrators
```

search for groups that probably has an admin privilege like "help desk" or "IT"
group like "Remote Desktop Users" is interesting too because it mean that we can connect via RDP and get GUI access

#### Existing users and groups

users:
```
# powershell
Get-LocalUser

# cmd
net user
```

return the local users that on the system and their activity (disable / enable)

groups: 
```
# powershell
Get-LocalGroup

# cmd
net group
```

return the local groups that on the system

note: 
- interesting group is _BackupUsers_ because they have extensive permissions to backup and restore all files on a computer, even those files they don't have permissions for.

- Members of **_Remote Desktop Users_** can access the system with RDP, while members of **_Remote Management Users_** can access it with _WinRM_.

to review the members of a specific group:
```
# powershell
Get-LocalGroupMember <group name>
```

#### Operating system, version and architecture 

```
systeminfo
[Environment]::Is64BitProcess
```

we wan to find:
- OS 
- version
- architecture (32/64) to know witch exe to run

#### Network information 

list all active network connections:
```
netstat -ano
netstat -tlpn
netstat -an | findstr "127.0.0.1:"
```

this can give us information about what running locally on the machine. port 80 of 443 for web server, 3306 for MYSQL server and more...

list all network interfaces:
```
ipconfig /all
```

information like DHCP configuration (yes/no), IP address, DNS server, gateway, subnet mask, and MAC address will be useful when we attempt to move to other systems or networks.

display the routing table:
```
route print
```

#### Installed applications 

**search for git 
```
.git files
keepass

# for example in powershell
Get-ChildItem -Path c:\ -Include .git,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

the idea of what installed and their versions is important for exploit vulnerability and find new vectors 

display 32-bit application:
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

display 64-bit application:
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

it is recommended to search in the path: "C:\\Program Files" and in "Downloads" directories

#### Running processes

processes run on five integrity levels

```
- System: SYSTEM (kernel, ...)
- High: Elevated users
- Medium: Standard users
- Low: Very restricted rights often used in sandboxed[^privesc_win_sandbox] processes or for directories storing temporary data
- Untrusted: Lowest integrity level with extremely limited access rights for processes or objects that pose the most potential risk
```

it is important to identify which of the applications are currently running
```
# powershell
Get-Process

# cmd
wmic process list full
```

due to the active process we can infer the purpose of the system

#### Running services

 check  services - won't work when using a network logon such as WinRM or a bind shell
```
# running
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# everyone
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# evil-winrm
services
```

 check under which user this service is running 
```
sc.exe qc <service name>
```

#### Scheduled Tasks

if the task runs as _NT AUTHORITY\SYSTEM_ or as an administrative user, then a successful attack could lead us to privilege escalation.

schedules tasks that not create by system
```
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' -and $_.Principal.UserId -ne 'SYSTEM' }
```

all tasks
```
schtasks /query /fo LIST /v
```

#### collect passwords

passwords usually can find in text file on the computer in files like meeting notes, configuration files, or onboarding documents.

to automate the search files we will use the following command:
```
Get-ChildItem -Path <path we want to search in> -Include <structure of files we looking for like: *.txt> -File -Recurse -ErrorAction SilentlyContinue

#for example
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

this is example of extension for "spray": txt,.pdf,.xls,.xlsx,.doc,.docx 

keepass database file
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

serach in registry
```
reg query HKLM /f password /t REG_SZ /s
```
#### history 

history of command save in:
- PowerShell Transcription
```
# PowerShell Transcription
PowerShell_transcript.<computername>.<random>.<timestamp>.txt.
type C:\Users\Public\Transcripts\transcript01.txt

Get-History

(Get-PSReadlineOption).HistorySavePath
```

#### Automated Enumeration

to speed up the enumeration phase we can use automation tools  like:
- winPEAS
- powerUp
```
. .\PowerUp.ps1
Invoke-AllChecks
```
- Seatbelt
- JAWS

