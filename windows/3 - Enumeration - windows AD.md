Our goal will be to enumerate the full domain, including finding possible ways to achieve the highest privilege possible (domain administrator in this case).

### Enumeration Using Legacy Windows Tools

Net Commands can be used to perform operations on Groups, users, account policies, shares, and so on. This command can't be used on domain controller. This command is only used on local computer.

enumerate privilege
```
whoami /priv
```

enumerate witch users in the domain
```
net user /domain
```

inspect specific user in the domain
```
net user <user_name> /domain
```

enumerate SID of the current user
```
whoami /user
```

enumerate group in the domain
```
net group /domain
```
pay attention to group that do not create by defaults

inspect specific group in the domain
```
net group "<group_name>" /domain
```

obtain the account policy
```
net accounts
```

change to domain user his password
```
net user /domain <user_name> <new_password>
```

Enumerate service account using **setspn.exe** that install by defaule
```
setspn -L <service name (sAMAccountName)>
for example: setspn -L iis_service
```

script to enumerate by LDAPQuery
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
	# Store the PdcRoleOwner name to the $PDC variable
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name

	# Store the Distinguished Name variable into the $DN variable
    $DistinguishedName = ([adsi]'').distinguishedName

	# build by LDAP format
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

example of use:
```
#list all the groups in the domain
LDAPSearch -LDAPQuery "(objectclass=group)"

#specific samAccountType
LDAPSearch -LDAPQuery "(samAccountType=805306368)"

#enumerate every group available in the domain and also display the user members
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
>> $group.properties | select {$_.cn}, {$_.member}
>> }

# members in specific groups 
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))" 
$sales.properties.member
```


### use PowerView.ps1 for enumeration

https://powersploit.readthedocs.io/en/latest/Recon/

###### Enumerating Domain:
```
Get-NetDomain
```

###### Enumerating Computers and OS:

```
Get-NetComputer
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Resolve-IPAdress <computer name>
```

###### Enumerating Users:

```
Get-NetUser | select samaccountname
Get-NetUser | select samaccountname,pwdlastset,lastlogon
```

Get usernames and their groups
```
Get-DomainUser -Properties name, MemberOf | fl
```
###### Enumerating Groups:

```
Get-NetGroup | select samaccountname
Get-NetGroup "Sales Department" | select member
```

###### Enumerating Permissions and open sessions

local admin, find if the current user is local admin on one of the computers in the domain
```
Find-LocalAdminAccess
```

check which user connect to which computer, to run this we may need to have certain permissions (this is maybe not work)
```
Get-NetSession -ComputerName <computer_name> -Verbose
```

replacement to Get-NetSession is the sysinternals tool named PsLoggedon that relay on _Remote Registry_ service (is not enable by default)
```
.\PsLoggedon.exe \\<computer_name>
```

###### Enumerating object permmitions
```
GenericAll: Full permissions on object - add users to a group or reset and change user's password, modify the User Account Control value of the user to not require Kerberos preauthentication and perform Targeted AS-REP Roasting, set an SPN for the user and preform targer kerberosting

GenericWrite: Edit certain attributes on the object - i.e logon script, modify the User Account Control value of the user to not require Kerberos preauthentication and perform Targeted AS-REP Roasting, set an SPN for the user and preform targer kerberosting

WriteOwner: Change ownership of the object - change object owner to attacker controlled user take over the object

WriteDACL: Edit ACE's applied to object - modify object's ACEs and give attacker full control right over the object

AllExtendedRights: Change password, reset password, etc. - ability to add user to a group or reset password

ForceChangePassword: Password change for object - - ability to change user's password

Self (Self-Membership): Add ourselves to for example a group - ability to add yourself to a group
```

enumerate ACEs - who has GenericAll permissions on the specify object
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
```
Get-ObjectAcl -Identity <user_name or group_name>

# enumerate object, check if he have GenericAll permissions:
Get-ObjectAcl -Identity <user_name or group_name> | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

# for example on domain admin
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

convert  SID/s to name
```
Convert-SidToName <SID>

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

enumerate specific permissions that are associated with Active Directory objects
```
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

users with GenericAll permission on domain admin
```
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
###### Kerberos

list kerberos tickets
```
klist
```

**AS-REP Roasting:** check if _Do not require Kerberos preauthentication_ enabled 
using powerview on windows:
```
Get-DomainUser -PreauthNotRequired
```

###### Enumerate service account:

Applications must be executed in the context of an operating system user. If a user launches an application, that user account defines the context. However, services launched by the system itself run in the context of a _Service Account_.
unique service instance identifier known as _Service Principal Name_ (SPN)[6](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/active-directory-introduction-and-enumeration/manual-enumeration-expanding-our-repertoire/enumeration-through-service-principal-names#fn6) associates a service to a specific service account in Active Directory.

To enumerate SPNs in the domain use **setspn.exe**, which is installed on Windows by default
```
setspn -L iis_service
```

using PowerView to enumerate all the SPN accounts in the domain
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

###### Enumerating Domain Shares

Domain shares often contain critical information about the environment

use PowerView to find the shares in the domain 
```
Find-DomainShare
```

list for example:
```
ls \\FILES04\docshare
```

using smbclient:
```
smbclient -L \\\\hostname.domain -I <hostname ip> -U domain/username
```

### sharphound & bloodhound

run sharphound
1. powershell version: Sharphound.ps1
2. exe version: https://github.com/BloodHoundAD/SharpHound

using powershell, after import:
```
.\SharpHound.exe

# powershell
. .\sharphound.ps1

Invoke-BloodHound -CollectionMethod All -OutputDirectory <Path> -OutputPrefix "<File_Name>"
```

run bloohound on kali
```
sudo neo4j start
bloodhound
```

clear the DB and upload sharphound files from the target computers
run quires on the data

enum:

```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
MATCH p=(u {owned: true})-[r1]->(n) WHERE r1.isacl=true RETURN p
```

domain admins
kerberosting - accounts
AS-REP acouunts

### enum4linux

```
enum4linux <DC IP>
```