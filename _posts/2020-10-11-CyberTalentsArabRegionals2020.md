---
published: True
layout: post
title:  "SaveTheWorld - Cybertalents ArabRegionals 2020"
author: Neroli
categories: Forensics, Web, ReverseEngineering
image: https://website-cybertalents.s3-us-west-2.amazonaws.com/Competitions/Thumbnail+-+Arab+and+Africa+CTF.jpg
beforetoc: "Arab Regionals 2020 Savetheworld challenge Writeup"
toc: true
---
# Name: Save the World
## Points: 200
## Level: Hard
## Solved: 0

# Memory Forensics
First of all we got Memory dump file called `it5_not_this_easy.mem` 

Running volatility on it to get the available profile:
`volatility -f it5_not_this_easy.mem imageinfo` :

![](https://user-images.githubusercontent.com/25514920/95689246-a0fe5f80-0c0f-11eb-9a29-bd0627929b47.png)

as we can see we got `Win7SP0x64` profile 

first thing that got into my mind is to find the process list
```
[neroli@neroli-pc solve]$ volatility -f it5_not_this_easy.mem --profile=Win7SP0x64 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa80003999b0 System                    4      0    100      510 ------      0 2020-10-06 15:40:37 UTC+0000                                 
....
....
0xfffffa8001899a00 notepad.exe            3936   2992      4       80      1      0 2020-10-06 15:49:53 UTC+0000                                 
0xfffffa80019b7b00 PurblePlace.ex          160   2992     10      201      1      0 2020-10-06 15:50:08 UTC+0000                                 
0xfffffa8001844b00 svshosts.exe           3496   2992      2       51      1      1 2020-10-06 15:50:25 UTC+0000                                 
0xfffffa8001834060 conhost.exe            3364    408      2       52      1      0 2020-10-06 15:50:25 UTC+0000                                 
0xfffffa80015bcb00 worm.exe               3416   2992      1       20      1      1 2020-10-06 15:50:29 UTC+0000                                 
0xfffffa80008b6060 conhost.exe            4088    408      2       53      1      0 2020-10-06 15:50:29 UTC+0000                                 
0xfffffa80019e4b00 trajon.exe             3312   2992      1       20      1      1 2020-10-06 15:50:31 UTC+0000                                 
0xfffffa80018f0b00 conhost.exe            3316    408      2       53      1      0 2020-10-06 15:50:31 UTC+0000                                 
0xfffffa8001923b00 WinRAR.exe             3444   2992      5      113      1      0 2020-10-06 15:50:36 UTC+0000                                 
0xfffffa8001950980 ransomware.exe         3864   2992      1       20      1      1 2020-10-06 15:50:37 UTC+0000                                 
0xfffffa80015175f0 conhost.exe            3412    408      2       53      1      0 2020-10-06 15:50:37 UTC+0000                                 
0xfffffa8001999060 malware.exe            1660   2992      1       20      1      1 2020-10-06 15:50:38 UTC+0000                                 
0xfffffa8001977b00 conhost.exe            1812    408      2       52      1      0 2020-10-06 15:50:38 UTC+0000                                 
[neroli@neroli-pc solve]$ 

```

There are many interesting processes, so let's get what is printed

```
[neroli@neroli-pc solve]$ volatility -f it5_not_this_easy.mem --profile=Win7SP0x64 consoles
Volatility Foundation Volatility Framework 2.6.1
**************************************************
ConsoleProcess: conhost.exe Pid: 3364
Console: 0xffac6200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\labib\Desktop\save_the_worled\svshosts.exe
Title: C:\Users\labib\Desktop\save_the_worled\svshosts.exe
----
CommandHistory: 0x7eef0 Application: svshosts.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x61310 X:80 Y:300
Dump:
you have been hacked successfully ;)                                            
hope u ll 3njoy this challing ;)                                                
press any key                                                                   
**************************************************
ConsoleProcess: conhost.exe Pid: 4088
Console: 0xffac6200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\labib\Desktop\save_the_worled\worm.exe
Title: C:\Users\labib\Desktop\save_the_worled\worm.exe
----
CommandHistory: 0x16eef0 Application: worm.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x151310 X:80 Y:300
Dump:
i know i looks sus but its not me , the malware is Amongus                      
**************************************************
ConsoleProcess: conhost.exe Pid: 3316
Console: 0xffac6200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\labib\Desktop\save_the_worled\trajon.exe
Title: C:\Users\labib\Desktop\save_the_worled\trajon.exe
AttachedProcess: trajon.exe Pid: 3312 Handle: 0x60
----
CommandHistory: 0x2feef0 Application: trajon.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x2e1310 X:80 Y:300
Dump:
do u think i looks like trojan                                                  
**************************************************
ConsoleProcess: conhost.exe Pid: 3412
Console: 0xffac6200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\labib\Desktop\save_the_worled\ransomware.exe
Title: C:\Users\labib\Desktop\save_the_worled\ransomware.exe
AttachedProcess: ransomware.exe Pid: 3864 Handle: 0x60
----
CommandHistory: 0x2eef20 Application: ransomware.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x2d1380 X:80 Y:300
Dump:
not me dont wast ur time                                                        
**************************************************
ConsoleProcess: conhost.exe Pid: 1812
Console: 0xffac6200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Users\labib\Desktop\save_the_worled\malware.exe
Title: C:\Users\labib\Desktop\save_the_worled\malware.exe
AttachedProcess: malware.exe Pid: 1660 Handle: 0x60
----
CommandHistory: 0x33ef00 Application: malware.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x321320 X:80 Y:300
Dump:
the meme were soooo funny , so i put this fun in the challenge , i hope u r have
ing the same fun now , this may be kind of hint                                 
[neroli@neroli-pc solve]$ 
```
having in mind that the flag description was talking about memes so it seems that 
`worm.exe` , `malware.exe` , `ransomware.exe`, `trajon.exe` are fake malwares 

so our target is `svshosts.exe` since it's similar to [scvhosts](https://en.wikipedia.org/wiki/Svchost.exe)
and also we now know that our path is `C:\Users\labib\Desktop\save_the_worled\`
so let's get the files list in this location
![](https://user-images.githubusercontent.com/25514920/95689453-2afaf800-0c11-11eb-976a-beba1eb0e8d8.png)

we can see that there is a rar file called `step2.rar` which was protected with password
![](https://user-images.githubusercontent.com/25514920/95689558-dad06580-0c11-11eb-91c6-fccf11f2c317.png)

now let's work with `svshosts.exe`
First thing i thought since it's a Forensics challenge we don't need to reverse the malware so i started with dumping the memory to find the encryption key or something which maybe the rar password so running `memdump`

`volatility -f it5_not_this_easy.mem --profile=Win7SP0x64 memdump -p 3496 -D .`

running `strings` on the dump file we got alot of informations like:

* msg from the malware:
```
hay bro , you have been hacked . 
dont worry you can recover your data for only 20.0 bc . 
if you are ok with this deal you can call us in this number +13370507458420053 
use the attached ID to recover your data .
if it waere you first tome with us , ask for you gift 
we have best castomer serves we are working 24//7.
good luck 
your ID is : Xt2J_dgz4_PRjM_53Rd_jSLS_fhTI
note for the challenge : this is a very safe program dont worry ;)
```
* alot of html pages which tells that the malware is dealing webserver
* webserver IP and Port and ID and Key:
```
Host: 18.156.199.115:3334
Connection: keep-alive
Content-Length: 74
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://18.156.199.115:3334
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://18.156.199.115:3334/mal/home.php 
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=s8jgn9u6j84qlrviq4mtddkn9b
id={NamYCAXTY2zHpYeX36YI0xvYEB5l&key=fMB0zjGbuQMnZOhAEq5Br9k&submit=Submit
```
* admin credentials and webserver endpoint:
```
Host: 18.156.199.115:3334
Connection: keep-alive
Content-Length: 42
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://18.156.199.115:3334
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://18.156.199.115:3334/mal/index.php 
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=s8jgn9u6j84qlrviq4mtddkn9b
username=admin&password=this_is_Admin_P@55
```
# WebApplication Exploitation


![](https://user-images.githubusercontent.com/25514920/95690379-9a73e600-0c17-11eb-8619-433e8958e875.png)
when i opened the webserver I got `nginx` welcome page 
moving to the endpoint we got a login page 
![](https://user-images.githubusercontent.com/25514920/95690413-e6bf2600-0c17-11eb-987e-9b304869aa15.png)

entering the credentials that we got gave me admin panel page 
![](https://user-images.githubusercontent.com/25514920/95690441-1bcb7880-0c18-11eb-95e3-ccb4c8e0d582.png)

entering the key and id that we got didn't help
![](https://user-images.githubusercontent.com/25514920/95690466-5df4ba00-0c18-11eb-82d6-de11e08f4a25.png)

after trying to find sqli in this page i got nothing 

but trying it on the login page using sqlmap i got a blind sqli 
![](https://user-images.githubusercontent.com/25514920/95690574-16226280-0c19-11eb-8550-e9cb0db9c3b9.png)

but the web server was going down every 3 mins so i gave up in the competition and they had released the full db file in the last 30 min but i was solving another challenge XD

now let's get back to work 

after going home the challenge went back again alive so let's continue 

getting the dbs:
![](https://user-images.githubusercontent.com/25514920/95690973-d315be80-0c1b-11eb-940d-7d4c10621c54.png)

I know already from the db file that we need to go for the `backup` table in `mal_w` db

I got alot of records and all of them was not readable and seemed encrypted 
![](https://user-images.githubusercontent.com/25514920/95691427-7916f800-0c1f-11eb-84ed-75426cb30522.png)

mm.. let's see again what we have:
* admin credentials
* password protected rar
* malware
* README with ID
# Reverse Engineering
now let's get back to the malware `svshosts.exe`

Running it was asking for a number and if we entered any number it outputs garbage data and crashes
![](https://user-images.githubusercontent.com/25514920/95691415-4ff66780-0c1f-11eb-90ab-a5d9b8401dea.png)

reversing the number function gave us this code:
```C
int *__fastcall sub_125530(void *Src, int a2)
{
  char magic_number; // bl
  int *v3; // esi
  int v4; // ecx
  unsigned int j; // edi
  unsigned int v6; // edx
  char v7; // al
  unsigned int v8; // ebx
  __int128 bytes; // [esp+10h] [ebp-210h]
  __int128 v11; // [esp+20h] [ebp-200h]
  __int128 v12; // [esp+30h] [ebp-1F0h]
  __int128 v13; // [esp+40h] [ebp-1E0h]
  __int128 v14; // [esp+50h] [ebp-1D0h]
  __int128 v15; // [esp+60h] [ebp-1C0h]
  __int128 v16; // [esp+70h] [ebp-1B0h]
  __int128 v17; // [esp+80h] [ebp-1A0h]
  __int128 v18; // [esp+90h] [ebp-190h]
  __int128 v19; // [esp+A0h] [ebp-180h]
  __int128 v20; // [esp+B0h] [ebp-170h]
  __int128 v21; // [esp+C0h] [ebp-160h]
  __int128 v22; // [esp+D0h] [ebp-150h]
  __int128 v23; // [esp+E0h] [ebp-140h]
  __int128 v24; // [esp+F0h] [ebp-130h]
  __int128 v25; // [esp+100h] [ebp-120h]
  __int128 v26; // [esp+110h] [ebp-110h]
  __int128 v27; // [esp+120h] [ebp-100h]
  __int128 v28; // [esp+130h] [ebp-F0h]
  __int128 v29; // [esp+140h] [ebp-E0h]
  __int128 v30; // [esp+150h] [ebp-D0h]
  __int128 v31; // [esp+160h] [ebp-C0h]
  __int128 v32; // [esp+170h] [ebp-B0h]
  __int128 v33; // [esp+180h] [ebp-A0h]
  __int128 v34; // [esp+190h] [ebp-90h]
  __int128 v35; // [esp+1A0h] [ebp-80h]
  __int128 v36; // [esp+1B0h] [ebp-70h]
  __int128 v37; // [esp+1C0h] [ebp-60h]
  __int128 v38; // [esp+1D0h] [ebp-50h]
  __int128 v39; // [esp+1E0h] [ebp-40h]
  __int128 v40; // [esp+1F0h] [ebp-30h]
  void *v41; // [esp+200h] [ebp-20h]
  int v42; // [esp+204h] [ebp-1Ch]
  int v43; // [esp+208h] [ebp-18h]
  int v44; // [esp+20Ch] [ebp-14h]
  char v45[4]; // [esp+210h] [ebp-10h]
  int v46; // [esp+21Ch] [ebp-4h]

  magic_number = a2;
  v42 = a2;
  v3 = Src;
  v44 = Src;
  v41 = Src;
  bytes = xmmword_12B010;
  v11 = xmmword_12AFF0;
  *(Src + 4) = 0;
  v12 = xmmword_12B030;
  *(Src + 5) = 15;
  v13 = xmmword_12AFA0;
  v14 = xmmword_12AF90;
  *Src = 0;
  v15 = xmmword_12B020;
  v16 = xmmword_12B170;
  v17 = xmmword_12B0A0;
  v18 = xmmword_12AFE0;
  v19 = xmmword_12B180;
  v20 = xmmword_12B0C0;
  v21 = xmmword_12B0E0;
  v22 = xmmword_12B090;
  v23 = xmmword_12B0D0;
  v24 = xmmword_12B100;
  v25 = xmmword_12B080;
  v26 = xmmword_12B150;
  v27 = xmmword_12B0F0;
  v28 = xmmword_12B040;
  v29 = xmmword_12B0B0;
  v30 = xmmword_12AFC0;
  v31 = xmmword_12B1A0;
  v32 = xmmword_12AFB0;
  v33 = xmmword_12AF60;
  v34 = xmmword_12AF70;
  v35 = xmmword_12AF50;
  v36 = xmmword_12AFD0;
  v37 = xmmword_12B190;
  v38 = xmmword_12B000;
  v39 = xmmword_12B160;
  v40 = xmmword_12AF80;
  s(Src, &dword_12A2ED, 0);
  v46 = 0;
  j = 0;
  v43 = 1;
  do
  {
    v6 = v3[4];
    v7 = magic_number ^ *(&bytes + 4 * j);
    v8 = v3[5];
    v45[0] = v7;
    if ( v6 >= v8 )
    {
      LOBYTE(v44) = 0;
      sub_127CF0(v3, v4, v44, v45[0]);
    }
    else
    {
      v3[4] = v6 + 1;
      v4 = v3;
      if ( v8 >= 0x10 )
        v4 = *v3;
      *(v4 + v6) = v7;
      *(v4 + v6 + 1) = 0;
    }
    magic_number = v42;
    ++j;
  }
  while ( j < 0x7C );
  return v3;
}

```

all what it was doing is using our number as a key to xor an array of bytes:
`array_of_bytes= ['0x2d', '0x25', '0x25', '0x2e', '0x6a', '0x20', '0x25', '0x28', '0x6a', '0x66', '0x26', '0x2f', '0x3e', '0x6a', '0x3e', '0x22', '0x2f', '0x6a', '0x29', '0x22', '0x2b', '0x26', '0x26', '0x2f', '0x24', '0x2d', '0x2f', '0x6a', '0x39', '0x3e', '0x2b', '0x38', '0x3e', '0x6a', '0x24', '0x25', '0x3d', '0x6a', '0x66', '0x6a', '0x3e', '0x22', '0x23', '0x39', '0x6a', '0x3a', '0x2b', '0x39', '0x39', '0x3d', '0x25', '0x38', '0x2e', '0x6a', '0x23', '0x39', '0x6a', '0x33', '0x25', '0x3f', '0x6a', '0x3d', '0x2b', '0x33', '0x6a', '0x3e', '0x25', '0x6a', '0x29', '0x25', '0x27', '0x3a', '0x26', '0x2f', '0x3e', '0x2f', '0x6a', '0x3c', '0x2f', '0x38', '0x39', '0x23', '0x25', '0x24', '0x6a', '0x74', '0x74', '0x6a', '0x6d', '0x23', '0x15', '0x24', '0x2f', '0x79', '0x2e', '0x15', '0x3e', '0x02', '0x2f', '0x15', '0x3c', '0x25', '0x26', '0x15', '0x27', '0x2f', '0x07', '0x25', '0x38', '0x33', '0x6d', '0x6a', '0x76', '0x76', '0x6a', '0x2d', '0x25', '0x25', '0x2e', '0x6a', '0x26', '0x3f', '0x29', '0x21']`

so with a simple bruteforce script we got the right key:
```python
array_of_bytes= ['0x2d', '0x25', '0x25', '0x2e', '0x6a', '0x20', '0x25', '0x28', '0x6a', '0x66', '0x26', '0x2f', '0x3e', '0x6a', '0x3e', '0x22', '0x2f', '0x6a', '0x29', '0x22', '0x2b', '0x26', '0x26', '0x2f', '0x24', '0x2d', '0x2f', '0x6a', '0x39', '0x3e', '0x2b', '0x38', '0x3e', '0x6a', '0x24', '0x25', '0x3d', '0x6a', '0x66', '0x6a', '0x3e', '0x22', '0x23', '0x39', '0x6a', '0x3a', '0x2b', '0x39', '0x39', '0x3d', '0x25', '0x38', '0x2e', '0x6a', '0x23', '0x39', '0x6a', '0x33', '0x25', '0x3f', '0x6a', '0x3d', '0x2b', '0x33', '0x6a', '0x3e', '0x25', '0x6a', '0x29', '0x25', '0x27', '0x3a', '0x26', '0x2f', '0x3e', '0x2f', '0x6a', '0x3c', '0x2f', '0x38', '0x39', '0x23', '0x25', '0x24', '0x6a', '0x74', '0x74', '0x6a', '0x6d', '0x23', '0x15', '0x24', '0x2f', '0x79', '0x2e', '0x15', '0x3e', '0x02', '0x2f', '0x15', '0x3c', '0x25', '0x26', '0x15', '0x27', '0x2f', '0x07', '0x25', '0x38', '0x33', '0x6d', '0x6a', '0x76', '0x76', '0x6a', '0x2d', '0x25', '0x25', '0x2e', '0x6a', '0x26', '0x3f', '0x29', '0x21']
for i in range(0xff):

    for e in array_of_bytes:

        try:
            print(chr(i ^ int(e,16) ) ,end="")
        except:
            pass
    print()
    print("-----------------------------",i)
```

which was `74`
and our output was:
`good job ,let the challenge start now , this password is you way to complete version >> 'i_ne3d_tHe_vol_meMory' << good luck`

and the program was still crashing so using `i_ne3d_tHe_vol_meMory` as a password for the rar file gaved us the fixed malware


![](https://user-images.githubusercontent.com/25514920/95691620-a4e6ad80-0c20-11eb-8dc4-abc9bf927a4c.png)

now let's reverse it, to be honest the strings part helped me alot since I know now what I need 

so I searched for the function which encrypts the data because our id in the readme file was not the same as the one in the httprequest above 
after some digging me and my team mate [alya](https://www.linkedin.com/in/alyagomaa/) found the encryption function at address `0x125310`:
```C
DWORD *_cdecl takes_our_id(void *Memory, int a2, int a3, int a4, int a5, int a6, void *admin, int a8, int a9, int a10, int sabet, int a12)
{
  _DWORD *v12; // ecx
  _DWORD *v13; // ebx
  int id_indices; // edi
  unsigned int i; // eax
  unsigned int len_of_alphabet; // ebx
  unsigned int integer; // ecx
  void **alphabet; // esi
  _DWORD *chrr; // eax
  int j; // edx
  bool boooool; // zf
  unsigned int k; // esi
  unsigned int v23; // edi
  unsigned int index_1; // edx
  bool idx; // cf
  void **alphabettt; // eax
  char *adminn; // ecx
  void **alphabet2; // ecx
  unsigned int idx2; // edx
  char chrrr; // al
  unsigned int v31; // ecx
  unsigned int v32; // edx
  _DWORD *encrypted_id; // eax
  void *v34; // ecx
  int v35; // edx
  _DWORD *Src; // [esp+14h] [ebp-2Ch]
  int v38; // [esp+20h] [ebp-20h]
  int INDEXXX; // [esp+24h] [ebp-1Ch]
  unsigned int key_indices; // [esp+28h] [ebp-18h]
  unsigned int v41; // [esp+2Ch] [ebp-14h]
  char v42; // [esp+30h] [ebp-10h]

  v13 = v12;
  Src = v12;
  v38 = v12;
  v12[4] = 0;
  v12[5] = 15;
  *v12 = 0;
  encrypt(v12, &dword_12A2ED, 0);
  id_indices = 0;
  i = 0;
  INDEXXX = 0;
  key_indices = 0;
  v41 = 0;
  if ( a5 )
  {
    do
    {
      len_of_alphabet = dword_12E058;
      integer = dword_12E05C;
      if ( dword_12E058 )
      {
        do
        {
          alphabet = &::alphabet;
          if ( integer >= 0x10 )
            alphabet = ::alphabet;
          chrr = takes_our_id_and_an_index(&Memory, i);
          boooool = *(alphabet + j) == *chrr;
          i = v41;
          integer = dword_12E05C;
          if ( boooool )
            id_indices = j;
        }
        while ( j + 1 < len_of_alphabet );
        INDEXXX = id_indices;
      }
      k = 0;
      if ( len_of_alphabet )
      {
        len_of_alphabet = dword_12E058;
        v23 = key_indices;
        index_1 = sabet - i % sabet;
        do
        {
          idx = integer < 0x10;
          alphabettt = &::alphabet;
          adminn = &admin;
          if ( !idx )
            alphabettt = ::alphabet;
          if ( a12 >= 0x10 )
            adminn = admin;
          boooool = *(alphabettt + k) == adminn[index_1 - 1];
          integer = dword_12E05C;
          if ( boooool )
            v23 = k;
          ++k;
        }
        while ( k < dword_12E058 );
        key_indices = v23;
        id_indices = INDEXXX;
      }
      alphabet2 = &::alphabet;
      if ( dword_12E05C >= 0x10 )
        alphabet2 = ::alphabet;
      idx2 = (id_indices + key_indices) % len_of_alphabet;
      v13 = Src;
      chrrr = *(alphabet2 + idx2);
      v31 = Src[4];
      v32 = Src[5];
      v42 = chrrr;
      if ( v31 >= v32 )
      {
        LOBYTE(v38) = 0;
        sub_127CF0(Src, v31, v38, chrrr);
      }
      else
      {
        Src[4] = v31 + 1;
        encrypted_id = Src;
        if ( v32 >= 0x10 )
          encrypted_id = *Src;
        *(encrypted_id + v31) = v42;
        *(encrypted_id + v31 + 1) = 0;
      }
      i = v41 + 1;
      v41 = i;
    }
    while ( i < a5 );
  }
  if ( a6 >= 0x10 )
  {
    v34 = Memory;
    if ( (a6 + 1) >= 0x1000 )
    {
      v34 = *(Memory - 1);
      v35 = a6 + 36;
      if ( (Memory - v34 - 4) > 0x1F )
      {
LABEL_34:
        invalid_parameter_noinfo_noreturn(v34, v35);
LABEL_35:
        sub_12895C(v34);
        return v13;
      }
    }
    sub_12895C(v34);
  }
  a5 = 0;
  a6 = 15;
  LOBYTE(Memory) = 0;
  if ( a12 >= 0x10 )
  {
    v34 = admin;
    if ( (a12 + 1) < 0x1000 )
      goto LABEL_35;
    v34 = *(admin - 1);
    v35 = a12 + 36;
    if ( (admin - v34 - 4) <= 0x1F )
      goto LABEL_35;
    goto LABEL_34;
  }
  return v13;
}
```


it was doing these steps:
* get the username `admin` and reverse It `nimda`
* find each character position in saved text let's call it `alphabet` = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_@` and save it, we renamed it as `key_indices`

* do the same for the `ID` which was written in `READMEEE.TXE` file and save it as `id_indices`
* then add each character location in `ID` to the corresponding character location in `nidma` and get `alphabet[sum]` and return the result text
* doing all of the above with the Values (that we got from the db) with the admin password `this_is_Admin_P@55`

so now let's decrypt it:
let `x` be our n'th char in `ID` and `y` our n'th char in `admin` and `c` the corresponding encrypted char, so:
`c = alphabet[(alpabet.index(x) + alphabet.index(y)) % len(alphabet)]`
then:
`x = alphabet[alphabet.index(c) - alphabet.index(y)]`

now to find the right record we can brute force to decrypt all of them or get the ID from the `notepad.exe` process we got 4 ID's:
![](https://user-images.githubusercontent.com/25514920/95692510-91d6dc00-0c26-11eb-8dd0-13961c4e8688.png)

encrypted all of them with:
```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_@"
def get_idx(string):
        indices=[]
        for i in range(len(string)):
            indices.append( alphabet.index(string[i]))
        return indices
def enc(inputt,key):
    id_indices = get_idx(inputt)
    key_indices = get_idx(key[::-1])

    for i in range(len(id_indices)):
        idx = (id_indices[i] + key_indices[i % len(key_indices)]) % len(alphabet)
        c= alphabet[idx]

        print(c,end="") 
    print()

IDS = ['Xt2J_dgz4_PRjM_53Rd_jSLS_fhTI', 'H2Pj_QlCx_X2Xp_KudH_fC2R_tU4c', 'y7c@_c4H7_lMiQ_{7zZ_a{2a_GMaC', 'k2dF_hAqd_gfn1_H6K8__saO_Ygdj']

for ID in IDS:
    enc(ID, 'admin')
```
output:
```
{NamYCAXTY2zHpYeX36YI0xvYEB5l
uW1_Y3FoMY{W9EYxOBkYEkauYS2c5
XbAcYBYtWYKuGtYjbX2Y@ea3Ytu_f
JWBiYGiO6YF@LQYuawXYlM_rY}AB_
```
the only one I found in the db was the last one which gaved me the `KEY`:
`Wc3v8HNQbikTUqMJEx3knNu1LIbh_V}{JIyrjflt5GCLY_wSO{HIu_3Vmym}f`

so I decrypted it:
```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_@"

def get_idx(string):
        indices=[]
        for i in range(len(string)):
            indices.append( alphabet.index(string[i]))
        return indices

def decrypt(encrypted, key):
    l = get_idx(encrypted)
    k = get_idx(key[::-1])
    for i in range(len(l)):
        x = l[i]
        x -= k[i%len(k)]
        print(alphabet[x],end='')
    print()

decrypt('Wc3v8HNQbikTUqMJEx3knNu1LIbh_V}{JIyrjflt5GCLY_wSO{HIu_3Vmym}f', 'this_is_Admin_P@55')
```

output:
`fl4g{its_imp0siplE_to_wOrk_hArd_foR_some7hin9_you_doNT_enjoY}`

And that's it XD, It was fun to solve after the ctf but it's not a Forensics only challenge So it would better have more points or be parted into 3 parts each part gives us a flag for a different category 

and also the webserver was going down a lot but it was fun to solve

I hope u all like it :)
