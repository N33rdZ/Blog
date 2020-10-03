---
layout: post
title:  "Cybertalents Egypt Finals 2020"
author: FlEx
categories: Web
image: https://raw.githubusercontent.com/N33rdZ/Blog/gh-pages/_posts/images/Key-Validate/bg-cy-ctf.jpg
---

## Web Challenges

### Name:
Cooki3 Sl4yer
### Level:
Easy
### Points: 
50

The servers is down so I can't show screenshots but I will share the idea of the challenge, the name of challenge show that we will play with the cookies
I opened the source code after opening the challenge and found a comment with `guest/guest` user, I logged in with it and take a look on the cookies and I found these two values
```
auth=Tzo0OiJVc2VyIjoyOntzOjQ6InVzZXIiO3M6NToiZ3Vlc3QiO3M6NDoicGFzcyI7czo1OiJndWVzdCI7fQ==
check=MGFkN2ZkNzVjMTE4ZTM4ZGY5ZTc3YzZiMWJmNWI5ZDI=
```
its a simple base64 decode it to be
```
auth:
O:4:"User":2:{s:4:"user";s:5:"guest";s:4:"pass";s:5:"guest";}
check:
0ad7fd75c118e38df9e77c6b1bf5b9d2
```
its a php serialization and another value i updated the serialization value to be `O:4:"User":2:{s:5:"admin";s:5:"guest";s:4:"pass";s:5:"guest";}` but didn't try it
and I copied the other value and start search with it on Google(my friend) and the amazing thing that I found a [write-up](https://trthien.wordpress.com/) to a simpler idea but with a non readable language
for me 😂, and I found the solution ready for me and it is
```
auth:
O:4:"User":2:{s:4:"user";s:5:"admin";s:4:"pass";b:1;}
check:
6897f0060a84ecb0600e4167d2a748e4
```
I encoded it to base64 and added it to the cookies and  I got my flag 😎.



### Name:
Icoan
### Level:
Medium
### Points: 
100

This challenge have same issue the server is down so I will share the idea of it, the challenge was including an upload function with a dropdown menu to select the format
of the uploaded file I tried a lot of payloads to upload a shell but I notice that the content-type of response is an image so there is two things first you should bypass it
second thing you are in a wrong road, I took a step back and I read the challenge description again and I notice that there is a `wizard` word and this is the big hint
it's `imageTragick`, how i knew? because it's logo is a wizard I used the website of [imageTragick](https://imagetragick.com/) to solve this challenge after trying a lot
of payloads I could read files on the server using this payload
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
```
I created a file with `mvg` extension and added the payload on it uploaded it and on the dropdown menu choose `MVG` and click upload, I took the request to repeater
and take look on the response it was an image but when I opened it `Render` it show an image with the passwd file but notice that I changed the size from 64 to 512 in the request

![1](https://raw.githubusercontent.com/N33rdZ/Blog/gh-pages/_posts/images/Key-Validate/psswd.png)

after that I tried `/etc/hosts, /etc/hostname, /etc/flag` and finally I found it in `/flag`, after that I notice a `readme.txt` and it tell you where is the flag 😂😂
but it wasn't hard to guess, and the flag was here

![2](https://raw.githubusercontent.com/N33rdZ/Blog/gh-pages/_posts/images/Key-Validate/flag.png)

and this is the end 😁.

The third challenge was hard no one solve it in the CTF (i think) but it was a SQl injection I was close to solve it but it's okay I will not share what I found on it
because it could be usd in another CTF.

GoodBye 👋👋.
