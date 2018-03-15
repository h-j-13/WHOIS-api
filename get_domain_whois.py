#!/usr/bin/env python
# encoding:utf-8

"""
    获取域名whois数据
=======================

version   :   1.0
author    :   @`13
time      :   2017.1.18
"""

import time
import Queue
import datetime
import threading

from Setting.global_resource import *  # 全局资源
from Setting.static import Static  # 静态变量,设置
from WhoisConnect import whois_connect  # Whois通信
from WhoisData.info_deal import get_result  # Whois处理函数
from Database.db_opreation import DataBase  # 数据库对象

Static.init()
Resource.global_object_init()
log_get_whois = Static.LOGGER

global domain_queue
domain_queue = Queue.Queue()
global WHOIS_queue
WHOIS_queue = Queue.Queue()


def get_domain_whois(raw_domain=""):
    """
    获取whois信息
    :param raw_domain: 输入域名
    :return: whois信息字典 / 获取失败返回None
    """
    log_get_whois.info(raw_domain + ' - start')

    # 处理域名信息
    Domain = Resource.Domain(raw_domain)
    # domain = Domain.get_utf8_domain()  # 用于返回显示的域名（utf8格式）
    domain_punycode = Domain.get_punycode_domain()  # punycode编码域名
    tld = Domain.get_tld()  # 域名后缀
    WhoisSerAddr = Resource.TLD.get_server_addr(tld)  # 获取whois地址,失败=None
    WhoisSerIP = Resource.WhoisSrv.get_server_ip(WhoisSerAddr)  # 获取whois地址的ip(随机取一个),失败=None
    WhoisFunc = Resource.WhoisFunc.get_whois_func(WhoisSerAddr)  # 获取TLD对应的提取函数名称

    log_get_whois.info('whois : ' +
                       str(WhoisSerAddr) +
                       '->' + str(WhoisSerIP) +
                       ' use:' + str(WhoisFunc))

    # 获取用于通信的whois服务器地址
    # 优先级 : ip > whois地址 > None (失败)
    WhoisConnectAddr = WhoisSerIP
    if WhoisConnectAddr is None:
        WhoisConnectAddr = WhoisSerAddr
    if not WhoisConnectAddr:
        log_get_whois.error(raw_domain + ' - fail : whois通信地址获取失败')
        return None

    # 获取原始whois数据
    raw_whois_data = ''  # 原始whois数据
    data_flag = 1  # whois通信标记
    try:
        raw_whois_data = whois_connect.GetWhoisInfo(domain_punycode, WhoisConnectAddr).get()
    except whois_connect.WhoisConnectException as connect_error:
        data_flag = 0 - int(str(connect_error))
    if raw_whois_data is None:
        data_flag = -5  # 获取到空数据，flag = -5

    # 处理原始WHOIS数据
    log_get_whois.info('flag : ' + str(data_flag))

    # 动态模版解析WHOIS数据
    whois_dict = get_result(domain_punycode,
                            tld,
                            str(WhoisSerAddr),
                            WhoisFunc,
                            raw_whois_data,
                            data_flag)

    log_get_whois.info(raw_domain + ' - finish')
    return whois_dict


def whois(raw_domain):
    """API核心函数 获取域名的WHOIS并记录日志"""
    start = time.time()
    result = get_domain_whois(raw_domain)
    end = time.time()
    if result:
        log_get_whois.error(raw_domain + " -> fin. in " + str(end - start)[:5] + " sec")
        return result
    else:
        log_get_whois.error(raw_domain + " -> error ")
        return {"domain": raw_domain,
                "error": "当前无法处理/无法解析的输入"}


def whois_list_thread():
    while not domain_queue.empty():
        WHOIS_queue.put(whois(domain_queue.get()))
    return


def whois_list(raw_domain_list):
    """API核心函数 批量获取域名的WHOIS并记录日志"""
    start = time.time()
    # 确定线程数
    raw_domain_list_length = len(raw_domain_list)
    thread_num = Static.WHOIS_THREAD_NUM
    if raw_domain_list_length < thread_num:
        thread_num = raw_domain_list_length
    # 填充任务队列
    global domain_queue
    global WHOIS_queue
    for raw_domain in raw_domain_list:
        domain_queue.put(raw_domain)
    # 开始多线程并发获取WHOIS
    thread_list = []
    for i in range(thread_num):
        get_whois_thread = threading.Thread(target=whois_list_thread)
        get_whois_thread.setDaemon(True)
        get_whois_thread.start()
        thread_list.append(get_whois_thread)
    for thread in thread_list:
        thread.join()
    # 结束
    end = time.time()
    log_get_whois.error("fin " + str(raw_domain_list_length) + " domains in " + str(end - start)[:5] + " sec")
    # 构造返回数据
    result_str = ""
    while not WHOIS_queue.empty():
        result_str += str(WHOIS_queue.get())
        result_str += ",\n"
    return result_str


if __name__ == '__main__':
    # Demo
    # print whois('baidu.com')
    print whois('baidu.com')
    # print whois_list(
    #     ['baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com',
    #      'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com',
    #      'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com',
    #      'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com',
    #      'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com',
    #      'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com',
    #      'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com',
    #      'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com',
    #      'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com',
    #      'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com',
    #      'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com',
    #      'acfun.com', 'douyu.com', 'qq.com', 'baidu.com', 'sina.com', 'acfun.com', 'douyu.com', 'qq.com'
    #      ])
