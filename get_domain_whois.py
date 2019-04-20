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
from Database.db_opreation import SQL_generate, DataBase, Update_WHOIS_record  # 数据库对象

Static.init()
Resource.global_object_init()
log_get_whois = Static.LOGGER

global domain_queue
domain_queue = Queue.Queue()
global WHOIS_queue
WHOIS_queue = Queue.Queue()

WHOIS_ERROR = {
    "0": "无法处理/未处理",
    "1": "正常",
    "-1": "一级WHOIS服务器通信出现问题",
    "-2": "二级WHOIS服务器通信出现问题",
    "-3": "未获取到二级WHOIS服务器"
}


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
    # WhoisSerIP = Resource.WhoisSrv.get_server_ip(WhoisSerAddr)  # 获取whois地址的ip(随机取一个),失败=None
    WhoisFunc = Resource.WhoisFunc.get_whois_func(WhoisSerAddr)  # 获取TLD对应的提取函数名称

    log_get_whois.info('whois : ' + str(WhoisSerAddr) + ' use:' + str(WhoisFunc))

    WhoisConnectAddr = WhoisSerAddr
    if not WhoisConnectAddr:
        log_get_whois.error(raw_domain + ' | ' + tld + ' - whois通信地址获取失败')
        return {'domain': domain_punycode, 'error': 'whois通信地址获取失败', 'flag': 0}

    # 获取原始whois数据
    raw_whois_data = ''  # 原始whois数据
    data_flag = 1  # whois通信标记
    try:
        raw_whois_data = whois_connect.GetWhoisInfo(domain_punycode, WhoisConnectAddr).get()
    except whois_connect.WhoisConnectException as connect_error:  # 二级whois解析过程错误记录
        data_flag = -1  # 一级错误

    # 处理原始whois数据
    whois_dict = get_result(domain_punycode,
                            tld,
                            str(WhoisSerAddr),
                            WhoisFunc,
                            raw_whois_data,
                            data_flag)
    log_get_whois.info(raw_domain + ' - finish')

    # save2db
    if whois_dict and 'flag' in whois_dict and whois_dict['flag'] == 1:  # 获取了正确的WHOIS数据
        Update_WHOIS_record(whois_dict)

    return whois_dict


def whois_from_db(domain):
    """从数据库查询whois"""
    with DataBase() as db:
        db.execute_no_return("""USE Beijing_WHOWAS""")
        whois = db.query_one(SQL_generate.QUERY_WHOIS(domain))
        if whois:
            whois_dict = {}
            for k, v in zip(
                    ['domain', 'sec_whois_srv', 'domain_status', 'registrar', 'reg_name', 'reg_phone', 'reg_email',
                     'org_name', 'name_server', 'reg_date', 'expir_date', 'updated_date'], whois):
                whois_dict[k] = str(v)
            whois_dict['name_server'] = whois_dict['name_server'].split(";")
            whois_dict["details"] = ""
            whois_raw = db.query_one(SQL_generate.QUERY_WHOIS_raw(domain))
            if whois_raw:
                whois_dict["details"] = whois_raw[1]
            whois_dict["top_whois_srv"] = ""
            domain = db.query_one(SQL_generate.QUERY_domain(domain))
            if domain:
                whois_dict["top_whois_srv"] = domain[1]
            return whois_dict
        else:
            return None


def whois(raw_domain):
    """API核心函数 获取域名的WHOIS并记录日志"""
    start = time.time()
    result = get_domain_whois(raw_domain)
    end = time.time()
    log_get_whois.error(raw_domain + " -> fin. in " + str(end - start)[:5] + " sec. flag:" + str(result['flag']))
    return result


def whois_list_thread():
    while not domain_queue.empty():
        WHOIS_queue.put(whois(domain_queue.get()))
    return


def format_WHOIS_record(WHOIS, source='QUERY', WHOIS_server=''):
    """格式化WHOIS记录"""
    result = {
        "domain": WHOIS['domain'],
        "reg_name": WHOIS['reg_name'],
        "registrant_organization": WHOIS['org_name'],
        "reg_email": WHOIS['reg_email'],
        "reg_phone": WHOIS['reg_phone'],
        "name_server": WHOIS['name_server'],
        "reg_date": WHOIS['reg_date'],
        "updated_date": WHOIS['updated_date'],
        "expir_date": WHOIS['expir_date'],
        "registrar": WHOIS['registrar'],
        "domain_status": WHOIS['domain_status'],
        "registrar_whois_server": [],
        "registrant_phone_ext": "",
        "reg_country": "",
        "reg_addr": "",
        "registry_domain_id": "",
        "registrar_url": "",
        "registrar_IANA_id": "",
        "registrar_abuse_contact_email": "",
        "registrar_abuse_contact_phone": "",
        "registry_registrant_id": "",
        "registrant_city": "",
        "registrant_state_province": "",
        "registrant_postal_code": "",
        "reg_fax": "",
        "registrant_fax_ext": "",
        "registry_admin_id": "",
        "adm_name": "",
        "admin_organization": "",
        "adm_addr": "",
        "admin_city": "",
        "admin_state_province": "",
        "admin_postal_code": "",
        "adm_country": "",
        "adm_phone": "",
        "admin_phone_ext": "",
        "adm_fax": "",
        "admin_fax_ext": "",
        "adm_email": "",
        "registry_tech_id": "",
        "tech_name": "",
        "tech_organization": "",
        "tech_adr": "",
        "tech_city": "",
        "tech_state_province": "",
        "tech_postal_code": "",
        "tech_country": "",
        "tech_phone": "",
        "tech_phone_ext": "",
        "tech_fax": "",
        "tech_fax_ext": "",
        "tech_email": "",
        "dnssec": "",
        'source': source
    }
    result_str = '{'
    if WHOIS['sec_whois_server']:
        result["registrar_whois_server"].append(WHOIS['sec_whois_server'])
    if WHOIS['top_whois_server']:
        result["registrar_whois_server"].append(WHOIS['top_whois_server'])
    # 字符串化
    for k, v in result.iteritems():
        # dict2json
        if k not in ["name_server", "registrar_whois_server", "domain_status"]:
            result_str += '"' + str(k) + '":"' + str(v) + '", '
        else:
            result_str += '"' + str(k) + '":['
            for vs in v:
                result_str += '"' + str(vs).replace('\n', '').replace('\r\n', '') + '", '
            result_str = result_str[:-2]
            result_str += "], "
    result_str = result_str[:-2]
    result_str += "}"
    return result_str


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
    log_get_whois.error("fin " + str(raw_domain_list_length) + " domains in " + str(end - start)[:6] + " sec")
    # 构造返回数据
    result_str = ""
    while not WHOIS_queue.empty():
        result_str += WHOIS_queue.get()
        result_str += "\n"
    return result_str


if __name__ == '__main__':
    # Demo

    print whois_from_db("baidu.com")

    # print whois('baidu.com')
    # print whois('bilibili.com')['details']
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
