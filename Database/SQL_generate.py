#!/usr/bin/env python
# encoding:utf-8

"""
    SQL 语句生成
======================

version   :   1.0
author    :   @`13
time      :   2017.3.23
"""


def get_table_num(domain):
    """获取域名所属分表序号"""
    table_num = -1
    # 抽取首字母
    domain = str(domain).lower()
    try:
        initial = domain[0]
    except:
        table_num = -1
        return table_num
    # 基于 http://172.29.152.152:8000/dns_domain/beijing_whowas/Database/blob/master/bjwazwa.md 的
    # 数据库设计分表原则进行分表
    if domain.find("xn--") != -1 and initial == "x":
        table_num = 7
    elif initial == "s" or initial == "q" or initial == "x":
        table_num = 1
    elif initial == "c" or initial == "v":
        table_num = 2
    elif initial == "m" or initial == "n":
        table_num = 3
    elif initial == "a" or initial == "i":
        table_num = 4
    elif initial == "t" or initial == "h":
        table_num = 5
    elif initial == "b" or initial == "j" or initial == "o":
        table_num = 6
    elif initial == "p" or initial == "g":
        table_num = 7
    elif initial == "d" or initial == "l":
        table_num = 8
    elif initial == "f" or initial == "w" or initial == "u" or initial == "y" or initial == "z":
        table_num = 9
    elif initial == "e" or initial == "r" or initial == "k":
        table_num = 10
    else:  # 数字
        table_num = 8
    return table_num


# SQL语句生成及优化
class SQL_generate:
    """
    SQL语句优化类
    """

    @staticmethod
    def PROXY_INFO(proxy_table_name):
        """
        :param proxy_table_name:代理ip表 
        :return: 获取代理socks的SQL语句
        """
        SQL = """SELECT whois_ip, proxy_ip, proxy_port, proxy_mode, message, speed FROM {PorxyTable}""".format(
            PorxyTable=proxy_table_name)
        return SQL

    @staticmethod
    def WHOIS_SRV_INFO(whois_srv_table_name):
        """
        :param whois_srv_table_name:whois服务器表 
        :return: 获取whois服务器ip地址的SQL语句
        """
        SQL = """SELECT svr_name, ip, port_available FROM {SvrIPTable}""".format(
            SvrIPTable=whois_srv_table_name)
        return SQL

    @staticmethod
    def TLD_WHOIS_ADDR_INFO(TLD_table_name):
        """
        :param TLD_table_name: TLD表
        :return: 获取TLD（顶级域）对应的whois服务器的SQL语句
        """
        SQL = """SELECT Punycode, whois_addr FROM {TLDtable}""".format(
            TLDtable=TLD_table_name)
        return SQL

    @staticmethod
    def INSERT_FQDN(domain, malicious_type='unknown', source='online'):
        return """INSERT IGNORE Beijing_WHOWAS.FQDN SET FQDN = '{f}',domain = '{d}',malicious_type='{mt}', source='{s}';""".format(
            f=domain, d=domain, mt=malicious_type, s=source
        )

    @staticmethod
    def INSERT_DOMAIN(whois_dict):
        SQL = """INSERT IGNORE Beijing_WHOWAS.`{table}` set """.format(
            table='domain_' + str(get_table_num(whois_dict['domain'])))
        SQL += """`TLD` = '{Value}', """.format(Value=whois_dict['tld'])
        SQL += """`top_whois_srv` = '{Value}', """.format(Value=whois_dict['top_whois_server'])
        SQL += """`whois_flag` = '{Value}', """.format(Value=whois_dict['flag'])
        SQL += """`domain` = '{Value}' """.format(Value=whois_dict['domain'])
        return SQL

    @staticmethod
    def INSERT_WHOIS_RAW(whois_dict):
        SQL = """INSERT IGNORE Beijing_WHOWAS.`{table}` set """.format(
            table='WHOIS_raw_' + str(get_table_num(whois_dict['domain'])))
        SQL += """`raw_whois` = '{Value}' ,""".format(Value=whois_dict['details'])
        SQL += """`domain` = '{Value}' """.format(Value=whois_dict['domain'])
        return SQL

    @staticmethod
    def INSERT_WHOIS(whois_dict):
        """
        :param whois_dict: whois 信息字典
        :param whois_table_name: whois表名
        :return: 插入whois表的SQL语句
        """
        SQL = """INSERT IGNORE Beijing_WHOWAS.`{table}` set """.format(
            table='WHOIS_' + str(get_table_num(whois_dict['domain'])))
        SQL += """`domain` = '{Value}', """.format(Value=whois_dict['domain'])
        SQL += """`domain_status` = '{Value}', """.format(Value=whois_dict['domain_status'])
        SQL += """`registrar` = '{Value}', """.format(Value=whois_dict['registrar'])
        SQL += """`sec_whois_srv` = '{Value}', """.format(Value=whois_dict['sec_whois_server'])
        SQL += """`reg_name` = '{Value}', """.format(Value=whois_dict['reg_name'])
        SQL += """`reg_phone` = '{Value}', """.format(Value=whois_dict['reg_phone'])
        SQL += """`reg_email` = '{Value}', """.format(Value=whois_dict['reg_email'])
        SQL += """`org_name` = '{Value}', """.format(Value=whois_dict['org_name'])
        SQL += """`name_server` = '{Value}', """.format(Value=";".join(whois_dict['name_server']))
        SQL += """`creation_date` = '{Value}', """.format(Value=whois_dict['reg_date'])
        SQL += """`expiration_date` = '{Value}', """.format(Value=whois_dict['expir_date'])
        SQL += """`updated_date` = '{Value}' """.format(Value=whois_dict['updated_date'])
        return SQL


if __name__ == '__main__':
    # Demo
    print SQL_generate.GET_WHOIS_INFO('baidu.com', ['details', 'flag'], 'whois')
    print SQL_generate.WHOWAS_TRANSFORM('whowas', 'whois', 'baidu.com')
