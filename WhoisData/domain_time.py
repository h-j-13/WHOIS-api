#!/usr/bin/env python
# encoding:utf-8

"""
    将域名获取的时间转换为标准时间
====================================

version   :   1.0
time      :   2017.8.25
"""

import pytz
from dateutil.parser import parse

utc_timezone = pytz.utc  # 设置utc时区

timezone_format = [
    '2016-07-16 23:06:34',
    '2015-01-05T13:27:16Z',
    '11-sep-2015',
    'Wed Aug 03 15:17:28 GMT 2016',
    '1997-09-15T00:00:00-0700',
    '1998-05-06 04:00:00+10',
    '23-Dec-2016 06:02:34 UTC',
    '2016/08/24',
    '2013-08-01',
    '24-12-2010',
]

def format_timestamp(str_time):
    """
    格式化时间
    """
    try:
        time_parse = parse(str_time)  # 解析日期为datetime型
    except ValueError, e:
        return str_time

    try:
        time_parse = time_parse.astimezone(tz=utc_timezone)  # 有时区转换为北京时间
    except ValueError, e:
        time_parse = utc_timezone.localize(time_parse)  # 无时区转换为localtime，即北京时间
    D, T = str(time_parse).split(" ", 1)
    return D + " " + T[:8]

if __name__ == "__main__":
    for i in range(len(timezone_format)):
        print format_timestamp(timezone_format[i])