# Forensics
## Burn the candle on both ends
一張jpg圖片，用binwalk檢查一下發現藏有一個zip文件是對flag.txt的壓縮。提取zip文件後，發現需要解壓密碼。

因爲題目描述說需要從兩端燃燒蠟燭，誤以爲密碼是藏在了圖片中，怎麼也找不到，比賽時止步於此。賽後看別人的writeup，發現是爆破的。。。

於是：
1. binwalk -e candle.jpg
2. zip2john 1944.zip > 1944.hashes
3. john 1944.hashes --wordlist rockyou.txt

解壓得到flag。

## Bucket 'o cash
給出鏈接`https://s3.amazonaws.com/ritsec-ctf-files/memorydump`可下載一個256M的memorydump文件，提出提示爲CentOS 7.5。

1. 用strings提取字符串，看到以下有趣的東西：
    ```
    overflow is detected
    grub rescure
    Linux 3.10.0-862.el7.x86_64 uhci_hcd
    WMware
    .text
    .rodata
    .bss
    .symtab
    x86_64-redhat-linux-gnu
    ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=630a050ff5721c66963b0a666b55a7b63175621b, stripped
    mv flag /home/memes/
    ./flag
    cp flag.c /home/memes/
    ```
    雖然信息很多，然而感覺無從下手。
2. 用binwalk分析，看到很多linux路徑輸出。但也沒什麼具體頭緒。
3. 用volatility分析，imageinfo沒有給出推薦結果，pslist、dumpfiles也都無法正常進行。

再次止步，等學了writeup後補充。

暈，看了writeup，離成功其實也不算遠，strings裏面我們感興趣的差不多就是後面volatility的分析指南。雖然volatility的imageinfo沒有給出結果，但是題目其實給了，而且strings裏面也能看出（`Linux 3.10.0-862.el7.x86_64 uhci_hcd`，Google知道爲CentOS 7.x），然後就是對volatility的熟練使用問題了。

1. volatility需要下載相應OS的profile才能有效工作，默認只只帶了Windows的（可以通過`volatility --info | grep Profile`查看）。Google搜索“volatility CentOS profile”，發現Github上就有，[下載](https://github.com/volatilityfoundation/profiles/blob/master/Linux/CentOS/x86/centos7-7.5.1804/Centos7-3.10.0-862.el7.x86_64.zip)放置與`/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux`目錄下。
1. 驗證安裝Profile成功。
```bash
$ volatility --info| grep Profile | grep Linux
Volatility Foundation Volatility Framework 2.6
LinuxCentos7-3_10_0-862_el7_x86_64x64 - A Profile for Linux Centos7-3.10.0-862.el7.x86_64 x64
1. 檢查一下進程情況。
```bash
$ volatility -f memorydump --profile=LinuxCentos7-3_10_0-862_el7_x86_64x64 linux_psaux
Volatility Foundation Volatility Framework 2.6
Pid    Uid    Gid    Arguments
1      0      0      /usr/lib/systemd/systemd --switched-root --system --deserialize 22
2      0      0      [kthreadd]
3      0      0      [ksoftirqd/0]
5      0      0      [kworker/0:0H]
6      0      0      [kworker/u256:0]
7      0      0      [migration/0]
8      0      0      [rcu_bh]
9      0      0      [rcu_sched]
10     0      0      [lru-add-drain]
11     0      0      [watchdog/0]
13     0      0      [kdevtmpfs]
14     0      0      [netns]
15     0      0      [khungtaskd]
16     0      0      [writeback]
17     0      0      [kintegrityd]
18     0      0      [bioset]
19     0      0      [kblockd]
20     0      0      [md]
21     0      0      [edac-poller]
22     0      0      [kworker/0:1]
27     0      0      [kswapd0]
28     0      0      [ksmd]
29     0      0      [crypto]
37     0      0      [kthrotld]
39     0      0      [kmpath_rdacd]
40     0      0      [kaluad]
41     0      0      [kpsmoused]
43     0      0      [ipv6_addrconf]
56     0      0      [deferwq]
87     0      0      [kauditd]
264    0      0      [mpt_poll_0]
265    0      0      [mpt/0]
266    0      0      [ata_sff]
274    0      0      [scsi_eh_0]
275    0      0      [scsi_tmf_0]
276    0      0      [scsi_eh_1]
279    0      0      [scsi_tmf_1]
281    0      0      [scsi_eh_2]
282    0      0      [scsi_tmf_2]
285    0      0      [ttm_swap]
287    0      0      [irq/16-vmwgfx]
358    0      0      [kdmflush]
359    0      0      [bioset]
369    0      0      [kdmflush]
370    0      0      [bioset]
382    0      0      [bioset]
383    0      0      [xfsalloc]
384    0      0      [xfs_mru_cache]
385    0      0      [xfs-buf/dm-0]
386    0      0      [xfs-data/dm-0]
387    0      0      [xfs-conv/dm-0]
388    0      0      [xfs-cil/dm-0]
389    0      0      [xfs-reclaim/dm-]
390    0      0      [xfs-log/dm-0]
391    0      0      [xfs-eofblocks/d]
392    0      0      [xfsaild/dm-0]
393    0      0      [kworker/0:1H]
459    0      0      /usr/lib/systemd/systemd-journald
481    0      0
482    0      0
506    0      0      [nfit]
530    0      0      [xfs-buf/sda1]
531    0      0      [xfs-data/sda1]
532    0      0      [xfs-conv/sda1]
533    0      0      [xfs-cil/sda1]
535    0      0      [xfs-reclaim/sda]
538    0      0      [xfs-log/sda1]
541    0      0      [xfs-eofblocks/s]
543    0      0      [xfsaild/sda1]
599    0      0
626    999    998
628    0      0      /usr/lib/systemd/systemd-logind
630    81     81     /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
636    998    996    /usr/sbin/chronyd
647    0      0      /usr/sbin/crond -n
652    0      1000
656    0      0
657    0      0      /usr/sbin/NetworkManager --no-daemon
992    0      0
993    0      0
994    0      0
1128   0      0
1140   89     89
1263   1000   1000
1284   0      0
1288   0      0
1329   89     89     pickup -l -t unix -u
1337   0      0
1339   0      0      tmux
1340   0      0      -bash
1355   0      0      -bash
1370   0      0
1484   0      0      [kworker/u256:1]
13153  0      0      /sbin/dhclient -d -q -sf /usr/libexec/nm-dhcp-helper -pf /var/run/dhclient-ens33.pid -lf /var/lib/NetworkManager/dhclient-5d98076d-95e2-4700-9cdd-fab7301cf613-ens33.lease -cf /var/lib/NetworkManager/dhclient-ens33.conf ens33
13476  0      0      [kworker/0:2]
13480  0      0      /sbin/agetty --noclear tty2 linux
13481  0      0      /sbin/agetty --noclear tty3 linux
13488  0      0      [kworker/0:0]
13498  0      0      ./flag
13500  0      0
```
./flag赫然在列。
1. 將該進程dump出來：
    ```bash
    $ volatility -f memorydump --profile=LinuxCentos7-3_10_0-862_el7_x86_64x64 linux_procdump --pid 13498 -D .
    Volatility Foundation Volatility Framework 2.6
    Offset             Name                 Pid             Address            Output File
    ------------------ -------------------- --------------- ------------------ -----------
    0xffff8ed8402cbf40 flag                 13498           0x0000000000400000 ./flag.13498.0x400000
    ```
1. 單獨分析這個文件：
```bash
$ strings flag.13498.0x400000
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
__libc_start_main
__gmon_start__
GLIBC_2.2.5
UklUU0VDH
e00zbTByH
D$ Cg==H
eV9GMHIzH
bnMxY3N9H
D$27
UH-0
UH-0
[]A\A]A^A_
;*3$"
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
__libc_start_main
__gmon_start__
GLIBC_2.2.5
UklUU0VDH
e00zbTByH
D$ Cg==H
eV9GMHIzH
bnMxY3N9H
D$27
UH-0
UH-0
[]A\A]A^A_
;*3$"
```
1. 其中H結尾的幾個字符串很像base64編碼。
```bash
$ strings flag.13498.0x400000 | grep H$ | base64 -d
RITSEC�4ʹ��pbase64: invalid input
```
1. 看來很接近了，有==的那一行應該在最後一行，先看看前面：
```bash
$ strings flag.13498.0x400000 | grep H$ | head -5 | sed -e 's/H$//' -e '/^D/d'| base64 -d
RITSEC{M3m0ry_F0r3ns1cs}
```
看來不用==就好。如果覺得這個方法有些撞運氣，寫個腳本爆破好啦。


1. [參考Writeup](https://github.com/flawwan/CTF-Writeups/blob/master/ritsec/bucketofcash/writeup.md)

## PCAP Me If You Can
根據題目描述，這應該是實現了一個私有協議。既然是私有協議，先看有沒有可以端口：
```bash
$ tshark -r *.pcapng -Tfields -e tcp.port | sort | uniq
22,33468
22,50644
33468,22
33758,443
34414,443
34416,443
...
80,57110
80,57122
80,57144
80,58646
8888,45826
8888,45828
8888,45830
8888,45832
8888,45838
8888,45852
8888,45854
8888,46062
8888,46078
8888,46114
```
8888端口顯然很可疑。提取會話：
```bash
$ tshark -r *.pcapng tcp.port==8888| sort| uniq | grep Len
13990  68.058515 172.16.140.131 → 172.16.140.1 TCP 74 45826 → 8888 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=2111755176 TSecr=0 WS=128
13991  68.058661 172.16.140.1 → 172.16.140.131 TCP 78 8888 → 45826 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 WS=32 TSval=676410590 TSecr=2111755176 SACK_PERM=1
13992  68.058814 172.16.140.131 → 172.16.140.1 TCP 66 45826 → 8888 [ACK] Seq=1 Ack=1 Win=29312 Len=0 TSval=2111755177 TSecr=676410590
13993  68.058874 172.16.140.1 → 172.16.140.131 TCP 66 [TCP Window Update] 8888 → 45826 [ACK] Seq=1 Ack=1 Win=131744 Len=0 TSval=676410591 TSecr=2111755177
13994  68.058952 172.16.140.131 → 172.16.140.1 TCP 112 45826 → 8888 [PSH, ACK] Seq=1 Ack=1 Win=29312 Len=46 TSval=2111755177 TSecr=676410590
13995  68.059025 172.16.140.1 → 172.16.140.131 TCP 66 8888 → 45826 [ACK] Seq=1 Ack=47 Win=131712 Len=0 TSval=676410591 TSecr=2111755177
13998  68.071416 172.16.140.1 → 172.16.140.131 TCP 74 8888 → 45826 [PSH, ACK] Seq=1 Ack=47 Win=131712 Len=8 TSval=676410603 TSecr=2111755177
13999  68.071475 172.16.140.1 → 172.16.140.131 TCP 66 8888 → 45826 [FIN, ACK] Seq=9 Ack=47 Win=131712 Len=0 TSval=676410603 TSecr=2111755177
14000  68.071634 172.16.140.131 → 172.16.140.1 TCP 66 45826 → 8888 [ACK] Seq=47 Ack=9 Win=29312 Len=0 TSval=2111755190 TSecr=676410603
14001  68.071832 172.16.140.131 → 172.16.140.1 TCP 66 45826 → 8888 [FIN, ACK] Seq=47 Ack=10 Win=29312 Len=0 TSval=2111755190 TSecr=676410603
14002  68.071904 172.16.140.1 → 172.16.140.131 TCP 66 8888 → 45826 [ACK] Seq=10 Ack=48 Win=131712 Len=0 TSval=676410603 TSecr=2111755190
14138  79.466505 172.16.140.131 → 172.16.140.1 TCP 74 45828 → 8888 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=2111766584 TSecr=0 WS=128
14139  79.466630 172.16.140.1 → 172.16.140.131 TCP 78 8888 → 45828 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 WS=32 TSval=676421949 TSecr=2111766584 SACK_PERM=1
14140  79.466742 172.16.140.131 → 172.16.140.1 TCP 66 45828 → 8888 [ACK] Seq=1 Ack=1 Win=29312 Len=0 TSval=2111766585 TSecr=676421949
14141  79.466801 172.16.140.1 → 172.16.140.131 TCP 66 [TCP Window Update] 8888 → 45828 [ACK] Seq=1 Ack=1 Win=131744 Len=0 TSval=676421950 TSecr=2111766585
14142  79.466844 172.16.140.131 → 172.16.140.1 TCP 117 45828 → 8888 [PSH, ACK] Seq=1 Ack=1 Win=29312 Len=51 TSval=2111766585 TSecr=676421949
```

有數據傳輸的是Len!=0的那些(tcp.len != 0)。
```bash
$ tshark -r *.pcapng -T fields -e tcp.port -e data tcp.port==8888 and tcp.len!=0
45826,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeadedf3f200
8888,45826	c3d0d0cdd09e1337
45828,8888	566572622e575249544500eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00a0f5e3eaea9ee6edf5e2f7a000
8888,45828	f5e3eaea9ee6edf5e2f79eadf2ebeeadedf3f2881337
45830,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeadedf3f200
8888,45830	c3d0d0cdd09e1337
45832,8888	566572622e575249544500eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00cdcbc59ee6edf59edff0e39ef7edf3bd00
8888,45832	cdcbc59ee6edf59edff0e39ef7edf3bd9eadf2ebeeadedf3f2881337
45838,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeadedf3f200
8888,45838	cdcbc59ee6edf59edff0e39ef7edf3bd9e881337
45852,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00f5e6eddfebe700
8888,45852	c3d0d0cdd09e1337
45854,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeadedf3f2b99ef5e6eddfebe700
8888,45854	cdcbc59ee6edf59edff0e39ef7edf3bd9e88e6f3eaf2ed881337
46062,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeade2dff2df00
8888,46062	d0c7d2d1c3c1f9d2e6aff1dde7f1ddcbf7ddcedfb3f1f5aef0e2ddd2e6b1f0e3dddff0e3ddcbdfecf7ddeae7e9e3dde7f2dde0f3b5ddf2e6e7b3ddafdde7f1ddebe7ece3fb881337
46078,8888	566572622e575249544500eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00f7aeeaae9eebdfec00
8888,46078	f7aeeaae9eebdfec9eadf2ebeeadedf3f2881337
46114,8888	566572622e5245414400eee3ecf2dface5edece300afb1b1b5e6dff6edf0f1d0e1aeaeea00adf2ebeeadedf3f200
8888,46114	f7aeeaae9eebdfec881337
```
可以看出服務器和客戶端之間一問一答還是蠻有規律的，而且客戶端的消息中前面的部分（第一個以C字符串）好像都是可打印字符，不妨驗證一下：

```bash
$ tshark -r *.pcapng -T fields -e data tcp.dstport==8888 and tcp.len!=0 | decode.py hex
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xed\xf3\xf2\x00'
b'Verb.WRITE\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xa0\xf5\xe3\xea\xea\x9e\xe6\xed\xf5\xe2\xf7\xa0\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xed\xf3\xf2\x00'
b'Verb.WRITE\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xcd\xcb\xc5\x9e\xe6\xed\xf5\x9e\xdf\xf0\xe3\x9e\xf7\xed\xf3\xbd\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xed\xf3\xf2\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xf5\xe6\xed\xdf\xeb\xe7\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xed\xf3\xf2\xb9\x9e\xf5\xe6\xed\xdf\xeb\xe7\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xe2\xdf\xf2\xdf\x00'
b'Verb.WRITE\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xf7\xae\xea\xae\x9e\xeb\xdf\xec\x00'
b'Verb.READ\x00\xee\xe3\xec\xf2\xdf\xac\xe5\xed\xec\xe3\x00\xaf\xb1\xb1\xb5\xe6\xdf\xf6\xed\xf0\xf1\xd0\xe1\xae\xae\xea\x00\xad\xf2\xeb\xee\xad\xed\xf3\xf2\x00'
```
不錯，看到了希望。進一步看出，客戶端的每一則消息都是由四個C字符串組成的，第一個字符串只有兩種指令：Verb.READ和Verb.WRITE，第二個和第三個字符串只有一種固定模式，最後一個字符串各不相同：
```bash
$ tshark -r *.pcapng -T fields -e data tcp.dstport==8888 and tcp.len!=0 | decode.py hex | sed -e 's/^..//' -e 's/.$//' -e 's/\\x00/\t/g' -e 's/\\x//g'
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeadedf3f2
Verb.WRITE	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	a0f5e3eaea9ee6edf5e2f7a0
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeadedf3f2
Verb.WRITE	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	cdcbc59ee6edf59edff0e39ef7edf3bd
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeadedf3f2
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	f5e6eddfebe7
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeadedf3f2b99ef5e6eddfebe7
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeade2dff2df
Verb.WRITE	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	f7aeeaae9eebdfec
Verb.READ	eee3ecf2dface5edece3	afb1b1b5e6dff6edf0f1d0e1aeaeea	adf2ebeeadedf3f2
```
服務器端的消息也很有意思，全部以十六進制1377結尾：
```bash
$ tshark -r *.pcapng -T fields -e data tcp.srcport==8888 and tcp.len!=0
c3d0d0cdd09e1337
f5e3eaea9ee6edf5e2f79eadf2ebeeadedf3f2881337
c3d0d0cdd09e1337
cdcbc59ee6edf59edff0e39ef7edf3bd9eadf2ebeeadedf3f2881337
cdcbc59ee6edf59edff0e39ef7edf3bd9e881337
c3d0d0cdd09e1337
cdcbc59ee6edf59edff0e39ef7edf3bd9e88e6f3eaf2ed881337
d0c7d2d1c3c1f9d2e6aff1dde7f1ddcbf7ddcedfb3f1f5aef0e2ddd2e6b1f0e3dddff0e3ddcbdfecf7ddeae7e9e3dde7f2dde0f3b5ddf2e6e7b3ddafdde7f1ddebe7ece3fb881337
f7aeeaae9eebdfec9eadf2ebeeadedf3f2881337
f7aeeaae9eebdfec881337
```
將多餘信息去掉，再次顯示通信過程，特徵將更加明顯：
```bash
$ tshark -r *.pcapng -T fields -e data tcp.port==8888 and tcp.len!=0 | decode.py hex | sed -e 's/^..//' -e 's/.$//' -e 's/\\x00/\t/g' | awk '{print $1, $4}' | encode.py hex | sed -e 's/566572622e5245414420/R /' -e 's/566572622e575249544520/W /'
R adf2ebeeadedf3f2
c3d0d0cdd09e1337
W a0f5e3eaea9ee6edf5e2f7a0
f5e3eaea9ee6edf5e2f79eadf2ebeeadedf3f2881337
R adf2ebeeadedf3f2
c3d0d0cdd09e1337
W cdcbc59ee6edf59edff0e39ef7edf3bd
cdcbc59ee6edf59edff0e39ef7edf3bd9eadf2ebeeadedf3f2881337
R adf2ebeeadedf3f2
cdcbc59ee6edf59edff0e39ef7edf3bd9e881337
R f5e6eddfebe7
c3d0d0cdd09e1337
R adf2ebeeadedf3f2b99ef5e6eddfebe7
cdcbc59ee6edf59edff0e39ef7edf3bd9e88e6f3eaf2ed881337
R adf2ebeeade2dff2df
d0c7d2d1c3c1f9d2e6aff1dde7f1ddcbf7ddcedfb3f1f5aef0e2ddd2e6b1f0e3dddff0e3ddcbdfecf7ddeae7e9e3dde7f2dde0f3b5ddf2e6e7b3ddafdde7f1ddebe7ece3fb881337
W f7aeeaae9eebdfec
f7aeeaae9eebdfec9eadf2ebeeadedf3f2881337
R adf2ebeeadedf3f2
f7aeeaae9eebdfec881337
```
在編輯器中稍作整理：
```bash
R                                       adf2ebeeadedf3f2
c3d0d0cdd0                          9e                      1337
-----------------------------------------------------------------------------------------------------------------------
W a0 f5e3eaea9ee6edf5e2f7 a0
     f5e3eaea9ee6edf5e2f7           9e  adf2ebeeadedf3f2 88 1337
-----------------------------------------------------------------------------------------------------------------------
R                                       adf2ebeeadedf3f2
c3d0d0cdd0                          9e                      1337
-----------------------------------------------------------------------------------------------------------------------
W cdcbc59ee6edf59edff0e39ef7edf3bd
  cdcbc59ee6edf59edff0e39ef7edf3bd  9e  adf2ebeeadedf3f2 88 1337
-----------------------------------------------------------------------------------------------------------------------
R                                       adf2ebeeadedf3f2
  cdcbc59ee6edf59edff0e39ef7edf3bd  9e                   88 1337
-----------------------------------------------------------------------------------------------------------------------
R                                                                             f5e6eddfebe7
c3d0d0cdd0                          9e                      1337
-----------------------------------------------------------------------------------------------------------------------
R                                       adf2ebeeadedf3f2            b9  9e    f5e6eddfebe7
  cdcbc59ee6edf59edff0e39ef7edf3bd  9e  88e6f3eaf2ed     88 1337
-----------------------------------------------------------------------------------------------------------------------
R                                       adf2ebeeade2dff2df
d0c7d2d1c3c1f9d2e6aff1dde7f1ddcbf7ddcedfb3f1f5aef0e2ddd2e6b1f0e3dddff0e3ddcbdfecf7ddeae7e9e3dde7f2dde0f3b5ddf2e6e7b3ddafdde7f1ddebe7ece3fb 88 1337
-----------------------------------------------------------------------------------------------------------------------

W f7aeeaae9eebdfec
  f7aeeaae9eebdfec                  9e  adf2ebeeadedf3f2 88 1337
-----------------------------------------------------------------------------------------------------------------------
R                                       adf2ebeeadedf3f2
  f7aeeaae9eebdfec                                       88 1337
```
注意到在R的應答中，有三條都是相同的'c3d0d0cdd0'（9e好像是某種消息的結束符，88是另外某種信息的結束符，1337是整個消息結束符），感覺像是某種狀態指示。常見狀態如OK、ERROR、SUCCESS，注意到其中很扎眼的三個'd0'，猜測應該是error或者ERROR。
```bash
cipher: c3 d0 d0 cd d0
string: E  R  R  O  R
ord(x): 45 52 52 4f 52
```
注意到c3-45=d0-52=cd-4f=7e。（如果是error，則差值爲0x5e）
```python
#!/usr/bin/python3
# -*- coding=utf8 -*-
with open('data.txt') as f:
    for line in f.readlines():
        line = line.strip()
        s = ''
        for i in range(0, len(line), 2):
            c = line[i:i+2]
            if c == '00':
                s += ' '
            else:
                s += chr(int(c, base=16) - 0x7e)
        print(s)
```
```bash
$ tshark -r *.pcapng -T fields -e data tcp.port==8888 and tcp.len!=0 | sed -e 's/566572622e5245414400//' -e 's/566572622e575249544500//' -e 's/1337$//' > data.txt
$ ./a.py
penta.gone 1337haxorsRc00l /tmp/out
ERROR
penta.gone 1337haxorsRc00l "well howdy"
well howdy /tmp/out

penta.gone 1337haxorsRc00l /tmp/out
ERROR
penta.gone 1337haxorsRc00l OMG how are you?
OMG how are you? /tmp/out

penta.gone 1337haxorsRc00l /tmp/out
OMG how are you?

penta.gone 1337haxorsRc00l whoami
ERROR
penta.gone 1337haxorsRc00l /tmp/out; whoami
OMG how are you?
hulto

penta.gone 1337haxorsRc00l /tmp/data
RITSEC{Th1s_is_My_Pa5sw0rd_Th3re_are_Many_like_it_bu7_thi5_1_is_mine}

penta.gone 1337haxorsRc00l y0l0 man
y0l0 man /tmp/out

penta.gone 1337haxorsRc00l /tmp/out
y0l0 man
```
得到flag（如果用error版本，輸出不全是可打印字符且類似亂碼）。

也可以通過猜測d0c7d2d1c3c1是RITSEC來得到同樣的結論，這是參考Writeup中的方法。

1. [參考Writeup](https://fireshellsecurity.team/ritsec-pcap-me-if-you-can/)
