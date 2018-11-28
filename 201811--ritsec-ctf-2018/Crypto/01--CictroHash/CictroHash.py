#!/usr/bin/python3
# -*- coding=utf8 -*-
import numpy as np
from Crypto.Random import get_random_bytes
from base64 import b64encode
from codecs import decode


def f(w):
    # w : ndarray of shape (2, 4)
    for i in range(50):  # 50 times
        # alpha: swap(w(0), w(1))
        w = np.concatenate((w[1], w[0])).reshape(2, 4)
        # beta
        w[0, 0] ^= w[1, 3]
        w[0, 1] ^= w[1, 2]
        w[0, 2] ^= w[1, 1]
        w[0, 3] ^= w[1, 0]
        # gama
        w = np.array([[w[1, 3], w[1, 0], w[1, 2], w[0, 0]],
                      [w[1, 1], w[0, 3], w[0, 1], w[0, 2]]], dtype=np.uint8)
        # delta: rotate
        # left
        w[0, 0] = ((w[0, 0] << 1) | (w[0, 0] >> 7)) & 0xFF
        w[1, 0] = ((w[1, 0] << 1) | (w[1, 0] >> 7)) & 0xFF
        w[0, 2] = ((w[0, 2] << 1) | (w[0, 2] >> 7)) & 0xFF
        w[1, 2] = ((w[1, 2] << 1) | (w[1, 2] >> 7)) & 0xFF
        # right
        w[0, 1] = ((w[0, 1] << 7) | (w[0, 1] >> 1)) & 0xFF
        w[1, 1] = ((w[1, 1] << 7) | (w[1, 1] >> 1)) & 0xFF
        w[0, 3] = ((w[0, 3] << 7) | (w[0, 3] >> 1)) & 0xFF
        w[1, 3] = ((w[1, 3] << 7) | (w[1, 3] >> 1)) & 0xFF
    return w


def CictroHash(s=''):
    # padding
    l = len(s)
    if l % 4 != 0:
        s += '\x00' * (4 - l % 4)
    l = len(s)
    # init w
    w = np.array([31, 56, 156, 167, 38, 240, 174, 248], dtype=np.uint8).reshape(2, 4)
    for i in range(0, l, 4):
        p = np.array([ord(c) for c in s[i:i+4]], dtype=np.uint8)
        w[0] ^= p
        w = f(w)
    z0 = w
    d = '0x' + ''.join(['%02x' % c for c in z0[0]])
    return d


if __name__ == "__main__":
    # import sys
    print(CictroHash("HELLOWORLD"))  # 0x91f1c05e
    print(CictroHash("GOODBYEWORLD"))  # 0x2a3e9123
    print(CictroHash("kUgKZMdQkn"))  # 0x7727b8d9
    print(CictroHash())  # 0x1f389ca7
    print(CictroHash("UIQ1UgiVv10="))
    print(CictroHash("2zfrGldfTzw="))
    # exit()
    table = {}
    i = 0
    while True:
        if i % 1000 == 0:
            print(i)

        m = get_random_bytes(8)
        m = b64encode(m)
        m = decode(m)
        h = CictroHash(m)
        if h in table and table[h] != m:
            print("CictroHash(%s) == CictroHash(%s) == %s" % (m, table[h], h))
            break

        table[h] = m
        i += 1

