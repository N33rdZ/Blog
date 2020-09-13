---
published: true
layout: post
title: ASCWG
author: Neroli
categories:
  - Crypto
image: >-
  https://user-images.githubusercontent.com/25514920/92043491-6b4a9900-ed7c-11ea-9342-50069438d4f1.png
beforetoc: Ascwg Crypto
toc: true
---
# Crypto Challenge with Number Theory

we are given python file which contains this code:

```python
flag = open("flag.txt","rb").read()
if len(flag) > 50:
    exit()

a = int.from_bytes(open("flag.txt","rb").read(), byteorder='big')

b = a << 99998
b = str(b)
if not b.endswith('46186384884704143502810449626149776675765629346197308004864280982758330594138478052711607866947764263543620513433238646216483214982856318892731845815726243647558073159634372394623630437969797570363392'):
    exit()
```

## Analysing the Script
To understand what is that first:
we need to know what is the [Logical Shift](https://en.wikipedia.org/wiki/Logical_shift)

so left shift means multiply by 2^n

for Ex:

x << 5 == x * 2^5

and second:
ends with means that we are using remainder with 10^(length of the string)

so let's write small equation
let `p = 46186384884704143502810449626149776675765629346197308004864280982758330594138478052711607866947764263543620513433238646216483214982856318892731845815726243647558073159634372394623630437969797570363392`

`b = a * 2^99998` , 
`b mod (10^len(p)) = p`

let's write math:
`p ≡ b mod(10^200)`


## Foctorizing and Modular multiplicative inverse

to solve this [Congruence](https://en.wikipedia.org/wiki/Modular_arithmetic#Congruence)
and find the [modinv](https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/)
we can use [fermat little theorem](https://www.geeksforgeeks.org/fermats-little-theorem/) but b and (2^200) are not [co-primes](https://en.wikipedia.org/wiki/Coprime_integers)

so we need to find a way, so after factoring using [factordb](http://factordb.com/) p we got

`p = 2^200 * 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829`

let's rewrite it:
`b = x * (10^200) + p`
so,
`b = x * (10^200) + 2^200 * 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829`

to reduce the `10` to something would be co-prime with `2` we can take the factor between them so,

since `b = a * 2^99998`

`a * 2^99998 = x * (10^200) + 2^200 * 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829`

`a * 2^99798 * 2^200 = x * (10^200) + 2^200 * 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829` 

dividing both sides with `2^200`

`a * 2^99798 = x * (5^200) + 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829`

let `u = 26 * 1265623 * 873448153343904364064230825514061770018600536286831235155141023388502830698662938149391708444890719584420535903183100333128864835829` 

so `a * 2^99798 = x * (5^200) + u`

which means 

`u ≡ a * (2^99798) mod(5^200)`
now it's easy to find the modinv using python 

```python
from Crypto.Util.number import long_to_bytes, inverse
l = pow(5,200)
p = 46186384884704143502810449626149776675765629346197308004864280982758330594138478052711607866947764263543620513433238646216483214982856318892731845815726243647558073159634372394623630437969797570363392
u = p // pow(2,200)
modinv = inverse(pow(2,99798,l),l)

flag = (u * modinv) % l
flag = long_to_bytes(flag)
print(flag)
```

which gave me the flag
# Flag
`ASCWG{Number_Ther0m_1s_1mportanmt_1n_Crypt0_12387}`
