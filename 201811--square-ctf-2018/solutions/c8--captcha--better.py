#!/usr/bin/python3
# -*- coding=utf8 -*-
"""
Created by SkyBlueEE on 2018-11-12.
"""
import sys, os
import base64
import requests as rq
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

r = rq.get("http://localhost:8082/ea6c95c6d0ff24545cad")
html = r.text
print(html)

head = html.find('base64,') + 7
tail = html[head:].find("'") + head
b64c = html[head:tail]

b64p = base64.b64decode(b64c)
with open('font.ttf', 'wb') as f:
    f.write(b64p)

os.system('ttx font.ttf')

font_root = ET.ElementTree(file='font.ttx')

symbol2name = {}
for e in font_root.iterfind('cmap/cmap_format_4/map'):
    symbol2name[int(e.attrib['code'], base=16)] = e.attrib['name']

name2value = {}
for e in font_root.iterfind('glyf/TTGlyph'):
    if e.attrib['name'] == 'glyph00000':
        continue
    name = e.attrib['name']
    xMax = e.attrib['xMax']
    yMax = e.attrib['yMax']
    if (xMax, yMax) == ("561", "689"):
        name2value[name] = "9"
    elif (xMax, yMax) == ("510", "696"):
        name2value[name] = "7"
    elif (xMax, yMax) == ("495", "519"):
        name2value[name] = "+"
    elif (xMax, yMax) == ("585", "660"):
        name2value[name] = "0"
    elif (xMax, yMax) == ("444", "481"):
        name2value[name] = "*"
    elif (xMax, yMax) == ("497", "704"):
        name2value[name] = "2"
    elif (xMax, yMax) == ("548", "684"):
        name2value[name] = "3"
    elif (xMax, yMax) == ("544", "679"):
        name2value[name] = "6"
    elif (xMax, yMax) == ("531", "690"):
        name2value[name] = "5"
    elif (xMax, yMax) == ("576", "690"):
        name2value[name] = "4"
    elif (xMax, yMax) == ("290", "747"):
        if e[0][0].attrib['x'] == '239':
            name2value[name] = "("
        elif e[0][0].attrib['x'] == '61':
            name2value[name] = ")"
        else:
            print("error )(")
    elif (xMax, yMax) == ("569", "689"):
        name2value[name] = "8"
    elif (xMax, yMax) == ("465", "347"):
        name2value[name] = "-"
    elif (xMax, yMax) == ("311", "673"):
        name2value[name] = "1"
    else:
        print("error unknown mark")

os.system('rm font.ttf font.ttx')


head = html.find('<h1>Captcha</h1><p>') + 19
tail = html[head:].find('</p>') + head
cipher = html[head:tail]

plain = ''
for c in cipher:
    if c == " ":
        continue
    plain += name2value[symbol2name[ord(c)]]

result = eval(plain)


soup = BeautifulSoup(html,'html.parser')
# token = next(e['value'] for e in soup.find_all('input') if e['name'] == 'token')
for e in soup.find_all('input'):
    if 'name' in e.attrs and e['name'] == 'token':
        token = e['value']

r = rq.post("http://localhost:8082/ea6c95c6d0ff24545cad", {"answer":result, 'token':token})
print(r.text)
