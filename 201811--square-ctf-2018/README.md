# Writeups
## C1. dot-n-dash
一道逆向題，需要根據編碼算法逆向推算出解碼算法，編碼函數：

考慮到輸入的都是ascii字符，最高比特位都是0，所以j==7時不會進入if，1+j范圍為1~7，所以b中的每個字符與(i, j)是一一對應的。

雖然后面用random進行打亂了順序，但是注意前面
```js
a.push(1 + j + (input.length - 1 - i) * 8);
```
已經對所編碼的字符在原字符串中的位置i和該字符的比特位j進行了保存，所以解碼并不依賴b中字符的排列順序，b中相同的i對應的是相同字符，不同的j對應該字符的1比特位。

## C2. flipping_bits
RSA密碼題目。給了同一個明文的兩個不同密文，分別對應了秘鑰$(e_1, n)$和$(e_2, n)$，注意$n$是相同的，同時$e_2$是將$e_1$的某一個比特位翻轉產生的，於是$e_1$和$e_2$互質，是一個針對RSA的共模攻擊(Common Modulus Attack)，基本原理如下：

$C_1 = M^{e_1} mod n$

$C_2 = M^{e_2} mod n$

當$gcd(e_1, e_2)=1$時，可以用拓展的歐几里得算法得到$(x, y)$，使得$xe_1 + ye_2 = 1$，於是：

${C_1}^x + {C_2}^y = M$

1. [攻擊腳本](https://github.com/a0xnirudh/Exploits-and-Scripts/blob/master/RSA%20Attacks/RSA:%20Common%20modulus%20attack.py)

## C3. shredded
題目給出了一個被切碎的二維碼，需要將該二維碼還原后提取信息。

首先放到gimp中按照二維碼的規則大致排一下，將一些可以確定位置的條紋確定位置，剩下不能確定的就很有限了，寫腳本窮舉一下即可。

1. [二維碼的生成細節和原理](https://coolshell.cn/articles/10590.html)
2. [二維碼生成原理及解析代碼](https://cloud.tencent.com/developer/article/1010480)

## C4. leaky_power
AES的邊信道攻擊，對功耗進行相關分析(CPA)。基本原理：

對於16比特長度明文的第i個比特，在進行第一輪列混淆之前只與秘鑰的第i個比特發生關系（異或后進行Sbox替換）。

給定同一個秘鑰加密的$D$個明文和相關的功耗記錄，利用AES加密的特點，功耗分析可以利用分治思想對16個比特逐比特進行并可以并行展開。

秘鑰的每個比特共有256中不同的可能，在給定的功率模型下，對每種可能的秘鑰比特k，$D$個明文都對應一個長度為$D$的功耗序列$X$。

對於長度為$T$的$D$個實際功耗記錄，對應了$T$個長度為$D$的功耗序列$[Y_1, Y_2, ..., Y_T]$。

計算$T$個$Y$序列和$X$之間的相關系數$[e_1, e_2, ..., e_T]$，其中

$$e_i=\frac{(X-EX)^T(Y_i-EY_i)}{\sqrt{(X-EX)^T(X-EX)}\sqrt{(Y_i-EY_i)^T(Y_i-EY_i)}} \in [-1, +1]$$

取絕對值最大的$|e_i|$作為該秘鑰比特k對應的最大相關系數。

由於k有256種可能，每種可能對應了一個最大相關系數，其中最大的那個對應的k即為具有最大可能性的密鑰比特。

最后將16個最大可能性的密鑰比特拼接起來，即可得到最為可能的密鑰。

得到密鑰后，對給的JWE文件進行解密即可得到明文flag。

1. [Correlation Power Analysis](https://wiki.newae.com/Correlation_Power_Analysis)
2. [Tutorial B6 Breaking AES (Manual CPA Attack)](https://wiki.newae.com/Tutorial_B6_Breaking_AES_(Manual_CPA_Attack))
3. [JWE文件解密](https://jwcrypto.readthedocs.io/en/latest/)

## C5 de-anonymization
非常簡單的社會工程學，所給的cvs文件中零散地分布着進行密碼重置所需要的所有元素，收集好進行密碼重置，flag就在返回網頁的url中。

## C6 gate-of-hell
這是一個用匯編寫的ELF32程序，釆用了特殊的跳轉使得無法進行反編譯，只能去理解匯編代碼。

1. 程序檢查argc是否大於16，小於等於16就退出，也即程序至少需要16個參數。
2. ebx初值為37，然后循環16次，每次針對一個參數，即多余16個參數是無用參數。16次循環結束后，檢查ebx是否為666(2×3×3×37)，相等則給出flag。
3. 每個循環執行如下操作：
    1. 將字符串參數轉換為十進制數字(首地址0x080481ca)，eax=atoi(argv[i])。
    2. 用aam和aad指令對eax中的數字進行檢查，不通過則將ebx置為0。
    3. 從keybox（0x080481ca開始的256個字節）中取出第eax個作為key，與ebx相乘結果存在ebx中。
    4. 更新keybox，將其中每個字節減1（如果某個字節已經為0，則不再更新該字節）。

觀察keybox初始值，最大值為16。則得到解題思路：程序以參數為索引不停取出更新后的key與r（初始值為37）相乘，乘16次后得到666就可得到flag；
我們設計參數使得乘2一次，乘3兩次，然后不停乘1即可得到flag。
由於可以有很多選擇，而aam和aad指令比較詭異，所以如果遇到將ebx置0的數字，另外選擇一組即可。
（所以我的代碼中最后有`if keys[n] == 1 and n != 23 and n != 37 and n!=79 and n!=126 and n!=134 and n!=140 and n!=143 and n!=146 and n!=147 and n!=156 and n!= 212:`一句，后面的n都是試出來的不滿足aam/aad檢查的。）

最后，flag實際上在服務器中，需要將參數用post方法傳給服務器（http://.../cgi-bin/gates-of-hell.pl后面加?后面跟着參數即可)。


## C7 gofuscated
一個go語言寫的逆向題目。分析代碼可知：
1. compute1()：給出一個動畫小人，對算法分析沒什么用。
2. compute2()：根據輸入字符串對一個100000大小的key空間進行100000輪操作得到最后的字符串，如果輸入正確，結果字符串即為flag。這個函數比較耗時。
3. compute3()：輸入是一個字符串，將該字符串中的相鄰重復字符過濾為1個（即bcceaaaad變為bcead）輸出。
4. compute4()：搆造一個小寫英文字符集合中的一一映射，然后將輸入字符串作為原像，轉換為值字符串。其中隨機函數種子固定為42，所以每次運行程序產生的映射是不變的。
5. panicIfInvalid()：可以看出函數僅接受英文和數字，長度必須是26（下稱有效字符串）。
6. another_helper()：檢查函數的輸入字符串是否按照ascii值進行從小到大排列。
7. main()：程序接受一個有效字符串參數，將該字符串輸入compute2計算flag的同時，進行如下操作：
    1. 利用compute3過濾該字符串，得到字符串(r，后又賦給input)也必須是一個有效字符串，於是輸入中不能有相鄰重復字母或數字。
    2. 利用compute4將input映射為其像值字符串，該像值字符串必須既是一個有效字符串，又滿足another_help檢查。
    3. 如果滿足上述條件，輸出flag。

通過上面的分析，很容易判斷出符合條件的像值字符串只能是順序排列的26個英文字母a-z，映射又是固定的（可以在compute4函數中添加printf語句輸出出來），
於是得到原像字符串nxelvzqaifsyhojudrbcwgptmk，用其作為參數運行程序即可得到flag。

## C8
給出一個動態驗證碼校驗的網頁(puzzles中給的只是其中一個實例，每次刷新網頁都不同)，要求輸入給定算式的結果，把算式拷貝出來發現居然是亂碼。

查看網頁代碼文件，發現原來網頁內嵌了一個很長的base64編碼的字符串，解碼后發現是一個ttf字體文件。原來出題者動態生成自定義的字體文件，然后利用該字體文件將英文亂碼字符串顯示為一個數學表達式。

於是問題變成了分析ttf文件，得到英文字符與數學字符之間的映射關系。

題目設置了超時機制，給的時間非常短，而本人能力所限，沒有給出一個全自動化的腳本，而是依靠拼湊的方案和手速通過了這一關。
當然，在這種拼湊的方案中，python再次顯示了其作為膠水語言的魅力。

1. 將瀏覽器中的網頁另存為a.html。
2. 從html文件中提取出base64字符串，解碼保存為font.ttf文件；提取出英文字符串，后面需要將其映射為數學表達式字符串。
3. 利用ttx程序將font.ttf轉換為font.ttx（實際上是一個xml文件）。
4. 通過解析ttx文件，得到數學字符與英文字符之間的映射。ttx文件中實際保存的是每個英文字符與其對應的字形（glyph），當然這里的字形實際畫出來是個數學字符。
5. 通過映射，得到英文字符串對應的數學表達式字符串，然后用eval函數計算該表達式的值。將結果存入系統剪切板。
6. 瀏覽器中ctrl-v粘貼結果，單擊提交，得到flag。

上面除了第1步和最后一步是手動實現的，其余都是通過單個腳本完成，比賽時另存為通過“右鍵-a（快捷鍵）-a（文件名）-回車”實現快速另存。第一次超時了，第二次通過了。

之所以還需要手動，是暫時還不會利用python腳本進行帶cookie和token的網絡交互，待學會了可以有更加完美的解決方案。

1. [A library to manipulate font files from Python](https://github.com/fonttools/fonttools)

## C9 postfuscator
postscript編程，這個冷門。。。還好其實只要求讀懂，并且確實用了并不多的語句。

ps文件其實是文本文件，可以用pdf打開，在linux下可以一邊編輯一邊實時預覽，還是蠻方便的，solution里面放了我調試過程的版本。

注意几點：
1. bash程序會對輸入進行過濾，只有0-9a-f（十六進制字符）才是有效輸入集合。
2. ps讀入有效輸入（前面加一個%字符），利用字符串'4L0ksa1t'循環異或進行加密，輸出前65個比特（這里稱作密文key）。
3. 程序內置了一個壓縮后的字符串，解壓后長度為118字節，放在buf中，可以利用show函數查看。
4. 利用buf對密文key進行檢驗，通過則給出flag：
    1. 初始值n=0，ok=0；
    2. 對密文key的每個字節c（值0~255），比較buf[n:n+len("%d"%c)]和c對應的數字字符串（"%d"%c），如果相等則ok+=len("%d"%c), n+=len("%d"%c)
    3. 如果最后n==118，則通過檢驗。

'flag-'+correct_input[2:2+20]為正確的flag。遍曆buf，與字符串循環異或，看輸出是否為十六進制字符即可。

1. [PostScript Wikipedia](https://en.wikipedia.org/wiki/PostScript)
2. [Thinking In PostScript](https://w3-o.cs.hm.edu/users/ruckert/public_html/compiler/ThinkingInPostScript.pdf)
3. [PostScript Language Reference 3rd](https://www.adobe.com/content/dam/acom/en/devnet/actionscript/articles/PLRM.pdf)

## C10 fixed-point
給出一個網頁，內含f(x)函數，其中x是個字符串，求這樣一個不動字符串x：f(x)=x。
提交不動字符串到在線網站上，驗證確實是不動字符串后給出flag。
```js
function f(x) {
  if ((x.substr(0, 2) == '🚀') && (x.slice(-2) == '🚀')) {
    return x.slice(2, -2);
  }
  if (x.substr(0, 2) == '👽') {
    return '🚀' + f(x.slice(2));
  }
  if (x.substr(0, 2) == '📡') {
    return f(x.slice(2)).match(/..|/g).reverse().join("");
  }
  if (x.substr(0, 2) == '🌗') {
    return f(x.slice(2)).repeat(5);
  }
  if (x.substr(0, 2) == '🌓') {
    var t = f(x.slice(2));
    return t.substr(0, t.length/2);
  }

  return "";
}
```

嚴格意義上講，這是我此次比賽中唯一一道沒解出的題目了（還有一道C4沒解出來是因為出題者一開始上傳錯了文件，后面更新后我一直沒下載替換。。。）。事后看了別人的writeup，比較好的思路是這個：

1. 首先f函數可以看作這樣一個過程：從第一個字符（這里把長度為2的emoji圖形稱作字符吧）開始向后數，如果可以繼續遞歸，則認為這個字符是一個操作字符，壓入操作符棧，這樣從前往后不停壓，直到剩下一個串A，頭尾都是火箭，那么這個A是最終的操作數，從操作符棧中不停彈出操作符作用於A，最后得到的字符串就是f的輸出。
2. 火箭是我們最終能終止壓棧的字符，外星人可以產生一個火箭，雷達用於逆序，兩個月亮都是用來進行長度操作的。
3. 📡📡是一個單位變換（不變變換）。
4. 📡👽📡的作用是將后面的字符串在尾巴上加上火箭（注意作用的先后順序應該是從右邊開始）。
5. 假設我們有這樣一個字符串x='A🚀A🚀'，其中A='B📡👽📡'且B中不含🚀，則🚀A🚀是最終的操作數，f(x)=A[f('🚀A🚀')]=B📡👽📡['A']=B['A🚀']，進一步，如果B只含月亮，則輸出就是'A🚀'重復若干次。
6. 🌗是重復5次，🌓是減半。假設有a次乘5操作，b次減半操作，最后得到x，則有$1\times 5^a / 2^b = 2$，但該方程，沒有整數解。
7. 假設串x='A🚀'×$n$，則最后f(x)=B['A🚀'×$(n-1)$]。有$(n-1)\times 5^a / 2^b = n$，有整數解$n=5, a=1, b=2$
8. 於是x='🌓🌓🌗📡👽📡🚀'×5='🌓🌓🌗📡👽📡🚀🌓🌓🌗📡👽📡🚀🌓🌓🌗📡👽📡🚀🌓🌓🌗📡👽📡🚀🌓🌓🌗📡👽📡🚀'為f(x)的其中一個不動字符串。


1. [參考writeup](https://github.com/ctf-epfl/writeups/tree/master/square18/c10_fixedpoint)
2. 這里還有一個[利用fuzzing的Writeup](https://github.com/nononovak/squarectf2018-writeup/blob/master/C10.md)也很有意思，號稱是第四名解出，比第一名只晚了13分鐘。
