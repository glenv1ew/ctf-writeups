Link: https://play.picoctf.org/practice/challenge/298?category=4&difficulty=3&page=1

# SideChannel

## Author: Anish Singhani
### Difficulty: Hard
### PicoCTF 2022
## Description:
```
There's something fishy about this PIN-code checker, can you figure out the PIN and get the flag?
Download the PIN checker program here pin_checker
Once you've figured out the PIN (and gotten the checker program to accept it),
connect to the master server using nc saturn.picoctf.net xxxxxx and provide it the PIN to get your flag.
```
### Tools used:
- Pyhton 3
- Kali Linux VM (Oracle VirtualBox)

## Solution:
The only file provided in this challange is the ```pin_checker``` binary. When we run it it asks for some 8 digit PIN.
```
$ ./pin_checker       
Please enter your 8-digit PIN code:
12345678
8
Checking PIN...
Access denied.

```

First of all I tried to revers engineer this binary. However, due to this is forensic challenge reverse does not work: disaassembler didn't give me any useful intel.
Then I tried the ```ltrace``` command to inspect what libraries this binary is using.
I got lots of Illegal instructions and segmantation faults. Code runs some invalid instruction to protect itself from being reverse engineered.
However, the ```gettimeofday``` line catched my eye.
```
gettimeofday(0x8877570, nil)                                                                                        = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
--- SIGSEGV (Segmentation fault) ---
gettimeofday(0x8877570, nil)                                                                                        = 0
--- SIGILL (Illegal instruction) ---
```
After I've made some search I tried the time based side channel attack. First of all we need to compare the amount of time program takes to check the password.
```
$ echo "20000000" | time  ./pin_checker
Please enter your 8-digit PIN code:
8
Checking PIN...
Access denied.

real    0.16s
user    0.11s
sys     0.05s
cpu     99%

$ echo "30000000" | time  ./pin_checker
Please enter your 8-digit PIN code:
8
Checking PIN...
Access denied.

real    0.16s
user    0.01s
sys     0.15s
cpu     99%


$ echo "40000000" | time  ./pin_checker
Please enter your 8-digit PIN code:
8
Checking PIN...
Access denied.

real    0.29s
user    0.20s
sys     0.08s
cpu     99%
```

Here is the difference - it takes more time to check the PIN with digit 4 at the start. 
Here comes the logic: more correct digits in the PIN = more time to proccess.

So, we can bruteforce the PIN using information on how long program proccesses users input.

I wrote a simple Python script, which does it automatically. If you wish to inspect the code, please refer to ```SideChannel.py``` file.

```
$ python3 SideChannel.py

 Found  4

 Found  48

 Found  483

 Found  4839

 Found  48390

 Found  483905

 Found  4839051

 Found  48390513

 Final pin: 48390513
```
So, we have a PIN, let's check it out.

```
$ ./pin_checker         
Please enter your 8-digit PIN code:
48390513
8
Checking PIN...
Access granted. You may use your PIN to log into the master server.

```
Alright ! Now we can get a flag.

```
nc saturn.picoctf.net 52042
Verifying that you are a human...
Please enter the master PIN code:
48390513
Password correct. Here's your flag:
picoCTF{t1m1ng_4tt4ck_914c5ec3}
```
That's it ! Pretty interesting challenge, that helps in understanding the time based attacks.


