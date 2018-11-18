#!/usr/bin/python3
# -*- coding=utf8 -*-

buf = '17120093678072186468590182921345215688056861272870'\
        + '89876612468382748236461208592688982686121828975882'\
        + '178245515674851882'
key = '4L0ksa1t'

n = 0
k = 0
# chr(17 ^ ord('4')) == '%'
n += 2
k += 1
input = ''
valid = ['%d' % i for i in range(10)] + ['a', 'b', 'c', 'd', 'e', 'f']
while n < 118:
    if buf[n] == '0':
        length = 1
        p = key[k]
        print("n = %d, length = %d, k='%c'" % (n, length, key[k]), flush=True)
        print("buf tail: " + buf[n:], flush=True)
        input += p
        print('input = ' + input, flush=True)
        print("=======================================================")
        k = (k + 1) % 8
        n = n + length
    for length in range(3, 0, -1):
        p = chr(int(buf[n:n+length]) ^ ord(key[k]))
        if p in valid:
            print("n = %d, length = %d, k='%c'" % (n, length, key[k]), flush=True)
            print('buf tail: ' + buf[n:], flush=True)
            input += p
            print('input = ' + input, flush=True)
            print("=======================================================")
            k = (k + 1) % 8
            n = n + length
            break
    else:
        print("error: n = %d, k = '%c'" % (n, key[k]), flush=True)
        print("error:" + buf[n:], flush=True)
        exit()
print('flag-' + input[2:2+20])
