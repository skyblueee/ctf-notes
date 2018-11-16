#!/usr/bin/python3
# -*- coding=utf8 -*-
"""
Created by SkyBlueEE on 2018-11-09.
"""
from skimage.io import imread, imshow, show, imsave
import numpy as np
from PIL import Image
from itertools import permutations
from pyzbar.pyzbar import decode
# import qrtools

# qr = qrtools.QR()
img = np.zeros((297, 10*27, 3), dtype=np.uint8)
cutted = np.zeros((297, 10, 3, 27), dtype=np.uint8)
# for i, name in enumerate([0, 9, 11, 5, 6, 25, 16, 2, 15, 26, 3]):
for i in range(27):
    cutted[:, :, :, i] = imread('%d.png' % i)

sure_idx = np.array([-2, -1, 0] + [1, 2] + [6, 7, 8, 11] + [14, 15, 16] + [20, 21, 22, 23, 24], dtype=np.uint8) + 3
sure_pic = [0, 0, 0, 5, 6] + [15, 26, 3, 21] + [7, 8, 1] + [18, 14, 0, 0, 0]

for i, idx in enumerate(sure_idx):
    img[:, 10*(idx-1):10*idx, :] = cutted[:, :, :, sure_pic[i]]

idx0 = np.array([3, 4, 5], dtype=np.uint8) + 3
pic0 = [25, 16, 2]

idx1 = np.array([9, 13], dtype=np.uint8) + 3
pic1 = [20, 23]

idx2 = np.array([17, 18, 19], dtype=np.uint8) + 3
pic2 = [22, 24, 4]

idx3 = np.array([10, 12], dtype=np.uint8) + 3
pic3 = [10, 19]

n = 0
for positions0 in permutations(idx0, len(idx0)):
    for i, pos in enumerate(positions0):
        img[:, 10*(pos-1):10*pos, :] = cutted[:, :, :, pic0[i]]
    for positions1 in permutations(idx1, len(idx1)):
        for i, pos in enumerate(positions1):
            img[:, 10*(pos-1):10*pos, :] = cutted[:, :, :, pic1[i]]
        for positions2 in permutations(idx2, len(idx2)):
            for i, pos in enumerate(positions2):
                img[:, 10*(pos-1):10*pos, :] = cutted[:, :, :, pic2[i]]
            for positions3 in permutations(idx3, len(idx3)):
                for i, pos in enumerate(positions3):
                    img[:, 10*(pos-1):10*pos, :] = cutted[:, :, :, pic3[i]]
                imsave("%d.bmp"%n, img)
                res = decode(Image.open('%d.bmp'%n))
                if res != []:
                    print(str(res[0].data, encoding='utf-8'))
                    # imshow(img)
                    # show()
                n += 1

