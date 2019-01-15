#!/usr/bin/env python
# encoding:utf-8

"""
基于pymysql的MySQL数据库操作封装

为了向上兼容py3及安装方便,弃用MySQLdb转用pymysql
MySQLdb : http://mysql-python.sourceforge.net/MySQLdb.html
pymysql : https://pypi.org/project/PyMySQL/
"""
# 优先使用pymysql,但是为了兼容性仍命名为MySQLdb
try:
    import pymysql as MySQLdb
except ImportError:
    import MySQLdb
from warnings import filterwarnings

from Setting.static import Static
from SQL_generate import SQL_generate
from WhoisData.domain_status import get_status_value

Static.init()
log_db = Static.LOGGER

filterwarnings('ignore', category=MySQLdb.Warning)  # 忽略警告


class DataBase:
    """MySQL数据库操作类"""

    def __init__(self):
        """数据库配置初始化"""
        # 连接参数
        self.host = Static.HOST
        self.port = Static.PORT
        self.user = Static.USER
        self.passwd = Static.PASSWD
        self.charset = Static.CHARSET  # 以后统一使用数据库默认编码
        self.timezone = "+8:00"
        # 链接对象
        self.conn = None
        self.cursor = None
        self.SSCursor = None

    def __enter__(self):
        self.db_connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 异常的 type、value 和 traceback
        if exc_val:
            log_db.error("DB Context Error:" + str(exc_val) + ":" + str(exc_tb))
        self.db_close()

    def db_connect(self):
        """连接数据库"""
        try:
            self.conn = MySQLdb.Connection(
                host=self.host,
                port=self.port,
                user=self.user,
                passwd=self.passwd,
                charset=self.charset,
                use_unicode=False,
                connect_timeout=2880000)
        except MySQLdb.Error, e:
            log_db.error('Connect Error:' + str(e))
        self.cursor = self.conn.cursor()
        self.SSCursor = self.conn.cursor(MySQLdb.cursors.SSCursor)
        if not self.cursor:
            raise (NameError, "Connect Failure")
        log_db.warning("MySQL Database(" + str(self.host) + ") Connect Success")

    def db_close(self):
        """关闭数据库"""
        try:
            self.cursor.close()
            self.SSCursor.close()
            self.conn.close()
            log_db.warning("MySQL Database(" + str(self.host) + ") Close")
        except MySQLdb.Error as e:
            log_db.error("Connect Error:" + str(e))

    def db_commit(self):
        """提交事务"""
        try:
            self.conn.commit()
            log_db.warning("MySQL Database(" + str(self.host) + ") Commit")
        except MySQLdb.Error as e:
            log_db.error("Commit Error:" + str(e))

    def execute_sql_value(self, sql, value):
        """
        执行带values集的sql语句
        :param sql: sql语句
        :param value: 结果值
        """
        try:
            self.cursor.execute(sql, value)
        except MySQLdb.Error, e:
            if e.args[0] == 2013 or e.args[0] == 2006:  # 数据库连接出错，重连
                self.db_close()
                self.db_connect()
                self.db_commit()
                log_db.error("execute |sql(value) - time out,reconnect")
                self.cursor.execute(sql, value)
            else:
                log_db.error("execute |sql(value) - Error:" + str(e))
                log_db.error("SQL : " + sql)

    def execute_no_return(self, sql):
        """
        执行SQL语句,不获取查询结果,而获取执行语句的结果
        :param sql: SQL语句
        """
        try:
            return self.cursor.execute(sql)
        except MySQLdb.Error, e:
            if e.args[0] == 2013 or e.args[0] == 2006:  # 数据库连接出错，重连
                self.db_close()
                self.db_connect()
                self.db_commit()
                log_db.error("execute |sql(no result) - time out,reconnect")
                self.cursor.execute(sql)
            else:
                log_db.error("execute |sql(no result) - Error:" + str(e))
                log_db.error("SQL : " + sql)

    def execute(self, sql):
        """
        执行SQL语句
        :param sql: SQL语句
        :return: 获取SQL执行并取回的结果
        """
        result = None
        try:
            self.cursor.execute(sql)
            result = self.cursor.fetchall()
        except MySQLdb.Error, e:
            if e.args[0] == 2013 or e.args[0] == 2006:  # 数据库连接出错，重连
                self.db_close()
                self.db_connect()
                self.db_commit()
                log_db.error("execute |sql - time out,reconnect")
                log_db.error("execute |sql - Error 2006/2013 :" + str(e))
                log_db.error("sql = " + str(sql))
                result = self.execute(sql)  # 重新执行
            else:
                log_db.error("execute |sql - Error:" + str(e))
                log_db.error('SQL : ' + sql)
        return result

    def execute_Iterator(self, sql, pretchNum=1000):
        """
        执行SQL语句(转化为迭代器)
        :param sql: SQL语句
        :param pretchNum: 每次迭代数目
        :return: 迭代器
        """
        log_db.info('执行:' + sql)
        __iterator_count = 0
        __result = None
        __result_list = []
        try:
            Resultnum = self.cursor.execute(sql)
            for i in range(Resultnum):
                __result = self.cursor.fetchone()
                __result_list.append(__result)
                __iterator_count += 1
                if __iterator_count == pretchNum:
                    yield __result_list
                    __result_list = []
                    __iterator_count = 0
            yield __result_list  # 最后一次返回数据
        except MySQLdb.Error, e:
            log_db.error('execute_Iterator error:' + str(e))
            log_db.error('SQL : ' + sql)

    def execute_many(self, sql, params):
        """
        批量执行SQL语句
        :param sql: sql语句(含有%s)
        :param params: 对应的参数列表[(参数1,参数2..参数n)(参数1,参数2..参数n)...(参数1,参数2..参数n)]
        :return: affected_rows
        """
        affected_rows = 0
        try:
            self.cursor.executemany(sql, params)
            affected_rows = self.cursor.rowcount
        except MySQLdb.Error, e:
            if e.args[0] == 2013 or e.args[0] == 2006:  # 数据库连接出错，重连
                self.db_close()
                self.db_connect()
                self.db_commit()
                log_db.error("execute |sql - time out,reconnect")
                log_db.error("execute |sql - Error 2006/2013 :" + str(e))
                log_db.error("sql = " + str(sql))
                self.execute_many(sql, params)  # 重新执行
            else:
                log_db.error("execute many|sql - Error:" + str(e))
                log_db.error('SQL : ' + sql)
                return -1
        return affected_rows

    def execute_SScursor(self, sql):
        """使用MySQLdb SSCursor类实现逐条取回
        请不要使用此方法来进行增、删、改操作()
        最好在with[上下文管理器内使用]"""
        # sql不要带 ';'
        # 有可能会发生 2014, "Commands out of sync; you can't run this command now"
        # 详见 [MySQL-python: Commands out of sync](https://blog.xupeng.me/2012/03/13/mysql-python-commands-out-of-sync/)
        sql = sql.strip(';')
        # 只能执行单行语句
        if len(sql.split(';')) >= 2:
            return []
        try:
            self.SSCursor.execute(sql)
            return self.SSCursor
        except MySQLdb.Error, e:
            log_db.error("execute SScursor |sql - Error:" + str(e))
            log_db.error('SQL : ' + sql)
            return []


def Update_WHOIS_record(WHOIS_dict):
    """
    更新WHOIS数据到数据库中
    :param WHOIS_dict: WHOIS数据字典
    """
    with DataBase() as db:
        db.execute_no_return(SQL_generate.INSERT_FQDN(WHOIS_dict['domain']))
        db.execute_no_return(SQL_generate.INSERT_DOMAIN(WHOIS_dict))
        WHOIS_dict['details'] = WHOIS_dict['details'].replace("\\", "").replace("'", " \\'").replace('"', ' \\"')
        db.execute_no_return(SQL_generate.INSERT_WHOIS_RAW(WHOIS_dict))
        WHOIS_dict['domain_status'] = get_status_value(";".join(WHOIS_dict['domain_status']))
        db.execute_no_return(SQL_generate.INSERT_WHOIS(WHOIS_dict))
        db.db_commit()


if __name__ == '__main__':
    # Demo
    with DataBase() as db:
        # Demo for execute
        # ------------------------------
        print db.execute("""show databases;""")

        # Demo for execute_Iterator
        # ------------------------------
        for results in db.execute_Iterator("""show databases;"""):
            for res in results:
                print res

        # Demo for execute_SScursor
        # ------------------------------
        for res in db.execute_SScursor("""show databases;"""):
            print res
