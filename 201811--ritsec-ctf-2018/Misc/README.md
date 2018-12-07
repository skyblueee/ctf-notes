# Misc
## Patch Patch
題目給出一個rpm文件和一個文本文件。文本文件指出在patch.c的fatal_exit函數中刪除了三行代碼：
```diff
diff -ur patch-2.7.1/src/patch.c patch-2.7.1.1/src/patch.c
--- patch-2.7.1/src/patch.c	2018-11-02 01:12:30.625613158 -0400
+++ patch-2.7.1.1/src/patch.c	2018-11-02 01:13:21.498608985 -0400
@@ -1953,9 +1953,9 @@
 fatal_exit (int sig)
 {
   cleanup ();
-#ifdef backdoor
-  printf("Looks like we got a vulnerability here");
-#endif
+
+/* Removed a super bad vuln here */
+
   if (sig)
     exit_with_signal (sig);
```
然而，用`file-roller --extract-here *.rpm`得到源碼中含有patch.c，就是patch後的代碼。

用grep搜索一下源代碼中的backdoor，發現一個RITSEC.patch，但不知道怎麼用。
```bash
$ grep -r backdoor *
patch-2.7.1-RITSEC.patch:+#ifdef backdoor
lj@kali:~/ctf-notes/201811--ritsec-ctf-2018/Misc/01--patch-patch/patch-2.7.1-10.el7.centos.src$ cat patch-2.7.1-RITSEC.patch
diff -ur patch-2.7.1/src/patch.c patch-2.7.1.1/src/patch.c
--- patch-2.7.1/src/patch.c	2018-11-02 00:12:12.109909934 -0400
+++ patch-2.7.1.1/src/patch.c	2018-11-02 00:13:58.740901189 -0400
@@ -1953,7 +1953,9 @@
 fatal_exit (int sig)
 {
   cleanup ();
-
+#ifdef backdoor
+  printf("Looks like we got a vulnerability here");
+#endif
   if (sig)
     exit_with_signal (sig);
```

PS: 有大神發現configure文件的第50行藏了這麼一句：
```Makefle
TEST=$(echo -e "\x55\x6b\x6c\x55\x55\x30\x56\x44\x65\x31\x5a\x56\x54\x45\x35\x54\x58\x7a\x52\x53\x4d\x31\x39\x43\x51\x55\x52\x66\x66\x51\x6f\x3d" | `echo -e "\x62\x61\x73\x65\x36\x34" -d`)
```
於是發現是base64加密的flag，解密得到flag。。。


## What_Th._Fgck
題目只有一句話：
```
OGK:DI_G;lqk"Kj1;"a"yao";fr3dog0o"vdtnsaoh"patsfk{+
```

Google沒有得到什麼有用信息，沒思路。

看了一下[別人的做法](https://github.com/flawwan/CTF-Writeups/blob/master/ritsec/whatthefuck/writeup.md)，搜其中的子串vdtnsaoh可以發現是另外一種鍵盤佈局，然後在線轉換就可以得到flag。

沒啥意思。

## RIP
程序給了一副圖片，binwalk、pngcheck都沒什麼問題，但圖片本身有一圈詭異邊框。
![RIP.png](./Misc/03--RIP/RIP.png)
該邊框是Piet編程。

從左上角開始，順時針提取邊框上的色塊，然後拼成一個png圖片，在線模擬程序，得到flag。
```python
from imageio import imread, imsave
import numpy as np

im = imread('./RIP.png')  # (910, 910, 4)
im = im[::10, ::10, :]

new_im = np.zeros((91 * 4 - 4, 4), dtype=np.uint8)

top91 = im[0, :, :]
print(top91)
bottom91 = im[90, :, :]
left89 = im[1:-1, 0, :]
right89 = im[1:-1, 90, :]

head = 0
tail = head + 91
new_im[head:tail] = top91
head += 91
tail = head + 89
new_im[head:tail] = right89
head += 89
tail = head + 91
new_im[head:tail] = bottom91[::-1, :]
head += 91
tail = head + 89
new_im[head:tail] = left89[::-1, :]

new_im.shape = (360, 1, 4)
imsave('a.png', new_im)
```

最後提一句，題目描述中的`+[----->+++<]>+.++++++++++++..----.+++.+[-->+<]>.-----------..++[--->++<]>+...---[++>---<]>.--[----->++<]>+.----------.++++++.-.+.+[->+++<]>.+++.[->+++<]>-.--[--->+<]>-.++++++++++++.--.+++[->+++++<]>-.++[--->++<]>+.-[->+++<]>-.--[--->+<]>-.++[->+++<]>+.+++++.++[->+++<]>+.----[->++<]>.[-->+<]>++.+++++++++.--[------>+<]>.--[-->+++<]>--.+++++++++++++.----------.>--[----->+<]>.-.>-[--->+<]>--.++++.---------.-.`是brainfuck編程語言，給出了一個youtube網站，據說裏面提到了border這個詞。


1. [Piet](https://esolangs.org/wiki/Piet)
1. [在線Piet模擬器](https://gabriellesc.github.io/piet/)
1. [參考Writeup](https://github.com/Gdasl/CTFs/blob/master/RITSEC2018/RIP.md)
1. [Brainfuck語言](https://en.wikipedia.org/wiki/Brainfuck)
1. [Brainfuck在線解析器](http://www.bf.doleczek.pl/)

## Check out this cool filter

給了一個YouTube鏈接和一張png圖片，鏈接裏的YouTube視頻是有廣告的。png未見異常，啥意思，不明所以。

賽後搜到[這個writeup](http://yocchin.hatenablog.com/entry/2018/11/19/204000)，大意是說視頻名字叫`Eiffel 65 - Blue (Da Ba Dee)`，所以和藍色通道相關（這線索有夠垃圾，不過確實stegsolve看藍色通道是和紅綠通道不一樣，明顯和圖像沒什麼關係，也算是我之前忽略了吧），

將藍色通道提取出來，發現都是重複的一串可打印字符，但不是flag，觀察前幾個字母的ord距離，可以判斷對應RITSEC，從而得到flag。

so much guessing work, boring!

## music.png
一看所給的圖片就不是什麼正常圖片，讀入後發現三個通道中的數據全部都是可打印字符串不停重複：
```python
rstr = '(t<<3)*[8/9,1,9/8,6/5,4/3,3/2,0]'
gstr = '[[0xd2d2c7,0xce4087,0xca32c7,0x8e4008]'
bstr = '[t>>14&3.1]>>(0x3dbe4687>>((t>>10&15)>9?18:t>>10&15)*3&7.1)*3&7.1]'
```
gstr多一個`[`而bstr多一個`]`，明顯應該拼在一起。

下面我就無所適從了，根據賽後其他人寫的writeup，可以Google該字符串得到網址[Music SoftSynth](https://gist.github.com/djcsdy/2875542)，可是我卻得不到什麼結果。

假設有了該網址，還要搜個在線播放器纔好，writeup中給出了一個：http://wry.me/bytebeat/

播放出聲音後，據說播放的是"Never Gonna Give You Up - Rick Astley"，所以flag是`RITSEC{never_gonna_give_you_up}`。不過我知識面顯然沒有那麼寬，而且用soundhount APP也搜索不出來，不過就這樣吧。

1. [參考writeup](https://github.com/sw1ss/ctf/blob/master/2018-11-19-RITSEC/Music.png/Readme.md)
