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
import traceback

from flask import Flask
from flask import request
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer

from Setting.static import Static
from get_domain_whois import whois, whois_list

Static.init()
app = Flask("WHOIS api")


@app.route('/')
def index():
    _result = "<h1>WHOIS api Service v0.1</h1>"
    _result += "<h3>author - h-j-13(@`13)</h5>"
    _result += "<h3>Harbin Institute of Technology at Weihai</h5> <br></br><br></br>"
    _result += ("<h5>system clock -> " + Static.get_local_time() + "</h5>")
    return _result


@app.route('/WHOIS/<domain>')
def WHOIS(domain):
    """获取单一域名的WHOIS数据"""
    # 总是现场查询
    data = {}
    try:
        data = whois(domain)
    except Exception as e:
        print "Error " + str(e.__class__) + " | " + e.message
        print "Error details : " + traceback.format_exc()
    return json.dumps(data, indent=1)


@app.route('/WHOIS/')
def WHOIS_list():
    """批量获取域名的WHOIS数据"""
    domain_list = request.args.get('domain_list', default='', type=str)
    return whois_list(domain_list.split(';'))


if __name__ == '__main__':
    # 利用tornado部署flask应用
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(Static.API_PORT, )
    IOLoop.instance().start()
