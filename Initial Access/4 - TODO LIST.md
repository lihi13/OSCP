
- [ ] nmap
	- [ ] domain name/sub domain
	- [ ] udp ports
		- [ ] check snmp port 161
	- [ ] other flags
	- [ ] http-enum
	- [ ] run nmap clear 
- [ ] enumerate directories  
	- [ ] other wordlist
	- [ ] other tool
	- [ ]  recursive dir enumeration
	- [ ] subdomains
- [ ] whatweb / appalyzer
	- [ ] server version
- [ ] source code website
- [ ] try to identify the framework (error page for example)
	- [ ] search version of services using burp suite
	- [ ] when identify enumerate directories  with the framework wordlist
	- [ ] search interasting file in github for open source framworks 
- [ ] check wordpress
- [ ] run nikto
- [ ] brute force ftp and smb (use admin:admin)
	- [ ] use the script to cat all files and search for creds
- [ ] if there are files in the website/shares run exiftool
- [ ] run burp
- [ ] check response header of a server
- [ ] search for git folder
- [ ] search login page
- [ ] Path Traversal
- [ ] search exploits in server, cms, ..
- [ ] try to write to one place read from another
- [ ] inspect packages with burp
- [ ] if the website convert to pdf use burp or exiftool on the file to see the library that used
- [ ] in phpinfo.php file 
	- [ ] search for web server root directory: ```$_SERVER['DOCUMENT_ROOT']```
	- [ ] search for web server disallow functions: ```disable_functions```
	- [ ] search for `allow_url_fopen` and `allow_url_include` both on for RFI
- [ ] file upload
	- [ ] use mspx if aspx is filtered
	- [ ] magic bytes
	- [ ]  change that content-type in burp suite
	- [ ] overwrite .htaaccess file and defile extension that render php
	- [ ] generate malicious file with the needed extension using tools  
	- [ ] upload file throw ftp or smb share and render from the website
	- [ ] search exploit in the service
	- [ ] read the code and see what are the terms to pass 
- [ ] search location of config/passwords/sql files in github repos for running services
- [ ] http put, options..
- [ ] LFI
	- [ ] use fuzzing `wfuzz -c --hh=32 -z file,/usr/share/wordlists/LFI_payload.txt http://<IP>:<PORT>/view?page=FUZZ `
	- [ ] check env `/etc/vsftpd.conf
	- [ ] running path `/proc/self/cmdline`
	- [ ] how can connect with ssh `/etc/ssh/sshd_config`
	- [ ] in windows search for potential users in the **website** and then search for keys in their folders `c:\users\<username>\.ssh\id_rsa`
	- [ ] located the file in /dev/shm (shared memory)
	- [ ] if it is .net web (maybe has .net deserialization) site search web.config file and run https://github.com/pwntester/ysoserial.net
	- [ ] search app.py to see that running and import
- [ ] RFI
	- [ ] in phpinfo file search for 'allow_url_fopen' and 'allow_url include' both on
- [ ] sqli
	- [ ] `wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/SQL.txt --hh 28 http://example.com/search?query=FUZZ`
- [ ] command injection
- [ ] if there is sql server port read the sql methods to search ideas
