#!/usr/bin/env python
# encoding:utf-8

"""
    主程序入口 - WHOIS api
=======================
WHOIS 查询api

version   :   0.1
author    :   @`13
time      :   2017.11.12
"""

import json
from flask import Flask

from Setting.static import Static
from get_domain_whois import whois

Static.init()
app = Flask("WHOIS_API")


@app.route('/')
def index():
    _result = "<h1>WHOIS api Service v0.1</h1>"
    _result += "<h3>author - h-j-13(@`13)</h5>"
    _result += "<h3>Harbin Institute of Technology at Weihai</h5> <br></br><br></br>"
    _result += ("<h5>system clock -> " + Static.get_local_time() + "</h5>")
    return _result


@app.route('/WHOIS/<domain>')
def WHOIS(domain):
    # show the user profile for that user
    return json.dumps(whois(domain), indent=1)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Static.API_PORT, debug=True)  # 开放公网
