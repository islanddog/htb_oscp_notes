# Cracking Windows Hashes #Windowsscree

## LM #LM-HASH
_Example_
```bash
299BD128C1101FD6
```
_Cracking it_
```bash
john --format=lm hash.txt  
hashcat -m 3000 -a 3 hash.txt
```

## NTHash (A.K.A. NTLM) #NT-HASH #NTLM
_Example_
```bash
B4B9B02E6F09A9BD760F388B67351E2B
```

_Cracking it_
```bash
john --format=nt hash.txt  
hashcat -m 1000 -a 3 hash.txt
```

## NTLMv1 (A.K.A. Net-NTLMv1) #NT-HASH #NTLMV1
_Example_
```bash
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

_Cracking it_
```bash
john --format=netntlm hash.txt  
hashcat -m 5500 -a 3 hash.txt
```

## NTLMv2 (A.K.A. Net-NTLMv2) #NTLMV2 #NT-HASH

_Example_
```bash
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

_Cracking it_
```bash
john --format=netntlmv2 hash.txt  
hashcat -m 5600 -a 3 hash.txt
```

## Linux Shadow #shadow

```txt
mark:$6$.n.:17736:0:99999:7:::
[--] [----] [---] - [---] ----
|      |      |   |   |   |||+-----------> 9. Unused
|      |      |   |   |   ||+------------> 8. Expiration date
|      |      |   |   |   |+-------------> 7. Inactivity period
|      |      |   |   |   +--------------> 6. Warning period
|      |      |   |   +------------------> 5. Maximum password age
|      |      |   +----------------------> 4. Minimum password age
|      |      +--------------------------> 3. Last password change
|      +---------------------------------> 2. Encrypted Password
+----------------------------------------> 1. Username
```



1.  Username. The string you type when you log into the system. The user account that exist on the system.
    
2.  Encrypted Password. The password is using the `$type$salt$hashed` format. `$type` is the method cryptographic hash algorithm and can have the following values:
    
    -   `$1$` – MD5
    -   `$2a$` – Blowfish
    -   `$2y$` – Eksblowfish
    -   `$5$` – SHA-256
    -   `$6$` – SHA-512
