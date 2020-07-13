
---
layout: post
title:  "FibSocket (Cybertalents Egypt FInals 2019)"
author: Neroli
categories: [ Reverse , Socket ]
image: https://user-images.githubusercontent.com/25514920/64659827-f5983f80-d43d-11e9-9b66-616f26d9204a.PNG
beforetoc: "Simple Socket server With Fibonacci sequence"
toc: true
---

# FibSocket Challenge

hello everyone my here is my solution for the FibSocket Challenge


## Category
Reaverse Engineering
## Level:
hard 
## Points: 
200
## File:
[FibSocket.exe](https://github.com/Neroli-realy/ctf/blob/master/Egypt2019/RE/FibSocket/FibSocket.exe)

## Solution

first thing get into my mind when i read the challenge name **Sockets** i said it's about server and client and it really was

at the competition i didn't think alot on this challenge and this was a big mistake :(

anyway when i open the file in **IDA** i got this main function and this **Code:** 

![1](https://user-images.githubusercontent.com/25514920/64659827-f5983f80-d43d-11e9-9b66-616f26d9204a.PNG)

which tells us this that listen port is **7777** in the ```htons()```

so i created a client wrote in c# to connect to this server through **localhost** and port **7777** which they told us as a **Hint**

now let's see the code of this server:

![3](https://user-images.githubusercontent.com/25514920/64659848-1791c200-d43e-11e9-89bc-897273438f2f.png)


and it's:

### -accepting the client and sending a **buffer** to it 
### -then it's going into a loop and sends another buffers with length 4
### -v27 and v26 are random values 
### -note that the dword_EB4024 is a **fibonacci sequence** starting from 3 
![4](https://user-images.githubusercontent.com/25514920/64659854-20829380-d43e-11e9-90ef-c2fd29382bcf.png)


if you don't know what is fibonacci numbers you can read this wiki [Fibonacci](https://en.wikipedia.org/wiki/Fibonacci_number)
## then receives an input and compare it with a random number from the squence if it's not equal .. it sends msg and disconnect

so i wrote a code which take what the server sends which is the random from **dword_EB4020**
and then search in the fibonacci nums to get it's index and resend it to the server to make the comparison returns true

```
 for (int i = 0; i < 1000; i++)
                    {
                        try
                        {

                            byte[] inStream = new byte[4];
                            Int32 bytes = s.Receive(inStream, inStream.Length, 0);
                            string st = "";
                            st = Encoding.UTF8.GetString(inStream, 0, bytes);
                            Console.Write(st);
                            if (i == 13)
                            {
                                var test = BitConverter.ToInt16(inStream, 0);
                                Console.WriteLine(test.ToString());
                                int indexOfNum = 0;

                                //just for debugging :)
                                foreach (char c in st)
                                    Console.WriteLine("{}==> " + ((int)c).ToString());
                                for (int t = 0; t < fibos.Length; t++)
                                {
                                    if (fibos[t] == (int)st[0])
                                    {
                                        indexOfNum = t;
                                        break;
                                    }
                                }

                                //first loop
                                int response = fibos[indexOfNum + 1];
                                var rawBytes = BitConverter.GetBytes(response);
                                //   uint send =  BitConverter.ToUInt32(rawBytes , 0);
                                // Console.WriteLine("{}==> " + send.ToString());
                                s.Send(rawBytes, rawBytes.Length, 0);
}
```

now we got to the second part

after this the server send's us a msg that we sent the write num and it's need the right byte:

![5](https://user-images.githubusercontent.com/25514920/64659868-309a7300-d43e-11e9-9159-a2f87862a5b8.png)

to be honest i didn't got this code but all what got into my head that it needs a right byte.....so the byte only take 255 

so i bruteforced it and the right one was 233

![6](https://user-images.githubusercontent.com/25514920/64659870-37c18100-d43e-11e9-8bfe-3361e0b0f0bc.png)


and here is the code i wrote for it :

![8](https://user-images.githubusercontent.com/25514920/64659880-4019bc00-d43e-11e9-86d9-7ebfa8e8a5f4.PNG)


and i got the flag :) 

 iam really not so good with RE ....yet and if there is any wrong in my saying just tell me i will be so grateful
 
 ## Flag
   TM{5702887,9227465}
