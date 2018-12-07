# Crypto
## CictroHash
給出了一個哈希算法的描述文檔，要求給出一個碰撞。按照文檔實現哈希算法之後暴力搜索即可。

## Nobody uses the eggplant emoji
感覺歸錯了類，難點不在於加解密，在於猜出題者的腦洞嘛。

題目給出的是一堆emoji文字，完全不明所以，說最後flag是RITSEC{key}，所以應該是一個加密的題目，要把密鑰搞到。

統計了一下，共有27個符號（算上原本就有的下劃線），所以猜測每個emoji對應一個英文字符。先隨意定義一個映射，得到ASCII形式的密文：

```python
emojis = '🤞👿🤓🥇🐼💩🤓🚫💪🤞🗣🙄🤓🥇🐼💩🤓😀✅😟🤓🍞🐼✅🚫💪🥇🤓🐼👿🤓🚫💪😟🤓👿😾😀😯🤓👿🤞✅🔥🚫🤓🥇🐼💩🤓👻💩🔥🚫🤓😀🗣🔥🍞😟✅🤓🚫💪😟🔥😟🤓🚫💪✅😟😟🤓💔💩😟🔥🚫🤞🐼🗣🔥😭🤓🍞💪😀🚫🤓🤞🔥🤓🥇🐼💩🤓🗣😀👻😟🤢🤓🍞💪😀🚫🤓🤞🔥🤓🥇🐼💩✅🤓💔💩😟🔥🚫🤢🤓🍞💪😀🚫🤓🤞🔥🤓🚫💪😟🤓😀🤞✅🤓🔥🐙😟😟😎🤓👀😟😾🐼🤬🤞🚫🥇🤓🐼👿🤓😀🗣🤓💩🗣😾😀😎😟🗣🤓🔥🍞😀😾😾🐼🍞😭🤓🥇🐼💩✅🤓👿😾😀😯🤓🤞🔥🤡🤓😀👿✅🤞🤬😀🗣_🐼✅_😟💩✅🐼🐙😟😀🗣_🔥🍞😀😾😾🐼🍞_🍞🐼🍞_🚫💪😟✅😟🔥_😀_😎🤞👿👿😟✅😟🗣🤬😟🤓'

emoji_set = set()
for c in emojis:
    if c not in emoji_set:
        emoji_set.add(c)
print(len(emoji_set))  # 27

table = {'_':'_'}
i = 0
for c in emojis:
    if c not in table:
        emoji_set.add(c)
        table[c] = chr(ord('a') + i)
        i += 1

s = ''
for c in emojis:
    s += table[c]
print(s)
```
得到：
```bash
abcdefcghaijcdefcklmcnelghdcebcghmcbokpcbalqgcdefcrfqgckiqnmlcghmqmcghlmmcsfmqgaeiqtcnhkgcaqcdefcikrmucnhkgcaqcdeflcsfmqgucnhkgcaqcghmckalcqvmmwcxmoeyagdcebckicfiokwmicqnkooentcdeflcbokpcaqzckblayki_el_mflevmki_qnkooen_nen_ghmlmq_k_wabbmlmiymc
```

[在線解密](https://www.guballa.de/substitution-solver)一下得到：
```bash
ifsyousthingsyousaresworthysofsthesflamsfirdtsyousjudtsandwersthedesthreesquedtiondpswhatsidsyousnajevswhatsidsyoursquedtvswhatsidsthesairsdbeekszelocitysofsansunlakensdwallowpsyoursflamsidxsafrican_or_eurobean_dwallow_wow_thered_a_kifferences
```

可以看到大概的結果了，還需要手動調整一下，比如s換成空格，k換成d等，[這個網站](https://www.dcode.fr/monoalphabetic-substitution)可以讓我們進行可視化的調整，最後結果：
```bash
if you think you are worthy of the flag first you must answer these three questions. what is you name? what is your quest? what is the air speed velocity of an unladen swallow. your flag is: african_or_european_swallow_wow_theres_a_difference
```
直接得到了flag。

1. 替換密碼在線解密：https://www.guballa.de/substitution-solver
2. 替換密碼動態解密：https://www.dcode.fr/monoalphabetic-substitution
3. 參考Writeup：https://medium.com/@ajdumanhug/ritsec-ctf-2018-writeup-miscforcry-f87812683227

## The Proof is in the Püdding
啥也沒說，只給了一頁pdf，裏面是一系列編號的聚類圖，猜不到作者腦回路，靜等大神的writeup吧。

## Lost In Transmission
給了一個字符串，看上去像base64加密，解密得到01串：
```bash
$ echo MTAxMTAxMDEwMTExMDEwMTAwMTAxMDEwMTExMTAxMDEwMTEwMTAxMDAxMDExMDEwMTAwMTExMTAxMDEwMTExMDAxMDEwMTAxMTEwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMDAwMDAxMDEwMTAwMDAwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMDAwMDAxMDEwMTAwMDAwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMTExMDAxMDEwMTAxMTEwMDEwMTAxMDEwMDExMDEwMTA= | base64 -d
10110101011101010010101011110101011010100101101010011110101011100101010111001010101001101010000000101010011110101000000101010000001010101001101010000000101010011110101000000101010000001010101001101010000000101010011110101011100101010111001010101001101010$ echo MTAxMTAxMDEwMTExMDEwMTAwMTAxMDEwMTExMTAxMDEwMTEwMTAxMDAxMDExMDEwMTAwMTExMTAxMDEwMTExMDAxMDEwMTAxMTEwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMDAwMDAxMDEwMTAwMDAwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMDAwMDAxMDEwMTAwMDAwMDEwMTAxMDEwMDExMDEwMTAwMDAwMDAxMDEwMTAwMTExMTAxMDEwMTExMDAxMDEwMTAxMTEwMDEwMTAxMDEwMDExMDEwMTA= | base64 -d | decode.py bin
b'-]J\xbdZ\x96\xa7\xab\x95r\xa9\xa8\n\x9e\xa0T\n\xa6\xa0*z\x81P*\x9a\x80\xa9\xea\xe5\\\xaaj'
```

下面猜不出了，不浪費時間了，靜等大神。

## Who drew on my program?
![program.png](./Crypto/05--program/crypto.png)

可以提取如下信息：
1. AES加密，CBC模式
2. 明文已知：'The message is protected by AES!'（32字节）
3. 密鑰(K='9aF738g9AkI112??')最後2个字节未知。
4. IV未知。
5. 密文中間13字节未知('9e??????????????????????????436a808e200a54806b0e94fb9633db9d67f0'(hexilified))。

由於是CBC模式，所以實際上是兩次AES加密：
1. 第一次，明文P1='The message is p'，與未知IV異或，經密鑰K的AES加密，密文C1='9e??????????????????????????436a'(hexilified)。
2. 第二次，明文P2='rotected by AES!'，與C1異或，經密鑰K的AES加密，密文C2='808e200a54806b0e94fb9633db9d67f0'(hexilified)。

解密時：
1. 將C1用K解密，與IV異或得到P1。
2. 將C2用K解密，與C1異或得到P2。

很明顯第二個分組有更多的信息，可以直接得到C2用K解密後的第0\14\15個字節，而C2已知，K只有兩個字節未知，於是可以直接窮舉猜解得到正確的K。得到K的同時C1也就已知了，用K解密C1，然後與P1異或，即可得到IV。
```python
bKEY = '9aF738g9AkI112'
p1 = b"The message is p"
p2 = b"rotected by AES!"
c1 = binascii.a2b_hex(b'9e00000000000000000000000000436a')
c2 = binascii.a2b_hex(b'808e200a54806b0e94fb9633db9d67f0')

for i in itertools.product(string.printable, repeat=2):
    eKEY = ''.join(i)
    KEY = bKEY + eKEY
    KEY = KEY.encode()
    aes = AES.new(KEY, AES.MODE_CBC, b'\x00'*16)
    xor = aes.decrypt(c2)
    if xor[0] == p2[0] ^ c1[0] and xor[14] == p2[14] ^ c1[14] and xor[15] == p2[15] ^ c1[15]:
        print("Got KEY: ", KEY)
        c1 = b''
        for i in range(16):
            c1 += (p2[i] ^ xor[i]).to_bytes(1, 'little')
        print('c1 =', c1)

        aes = AES.new(KEY, AES.MODE_CBC, b'\x00'*16)
        xor = aes.decrypt(c1)
        IV = b''
        for i in range(16):
            IV += (p1[i] ^ xor[i]).to_bytes(1, 'little')
        print('IV =', IV)
```

## DarkPearAI
謎之題幹：
```
3:371781196966866977144706219746579136461491261

Person1: applepearblue
Person2: darkhorseai

What is their secret key?
(Submit like RITSEC{KEY_GOES_HERE})

Hint 1: Hopefully you can get the flag in a <s>diffie</s> jiffy!

Hint 2: If you can type at a decent pace this challenge can be completed in under 30 seconds
```

看了別人的答案才知道是Diffie-Hellman，好吧，Hint1我沒有完全領會，但是在這裏卡這麼一道真的有意思麼？
```
g = 3
n = 371781196966866977144706219746579136461491261
Person1: applepearblue
Person2: darkhorseai
```

重溫一下DF密鑰交換要點：利用離散對數，戴金箍容易摘金箍難。
1. A選擇$a$，發送$g^a$；
2. B選擇$b$，發送$g^b$；
3. AB將$K=g^{ab}$作爲密鑰。

由於這裏n比較小，應該可以用sage直接計算離散對數：
```sage
n=371781196966866977144706219746579136461491261
F = IntegerModRing(n)

g=3
ga = int(binascii.hexlify('applepearblue'.encode()), base=16)  # 7719929996562228520753654691173
gb = int(binascii.hexlify('darkhorseai'.encode()), base=16)  # 121352762178684172934406505

a = discrete_log(F(ga), F(g))
b = discrete_log(F(gb), F(g))

print('RITSEC{'+str(IntegerModRing(n)(g)**(a*b))+'}')
```
沒想到報錯：“No discrete log of 7719929996562228520753654691173 found to base 3”。

左思右想不明白，只好又繼續看別人的答案，原來applepearblue變成10進制數的方法是這樣的：直接將每個字母變成10進制數字最後拼接，而不是我那樣將每個字母變成16進制拼接後轉換爲10進制。於是：
```sage
ga = 97112112108101112101097114098108117101
gb = 100097114107104111114115101097105
```

本題是密碼題分值最高的題（500分），DF交換不是難點，兩個腦洞纔是得分關鍵。
