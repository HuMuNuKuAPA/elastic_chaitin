#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
# 日期：2023年5月9日
from pprint import pprint
import requests
import json
import hashlib
import urllib3
import re
import datetime
import os
import smtplib
import email.utils
from requests.cookies import RequestsCookieJar
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.utils import formataddr
from jinja2 import Environment, FileSystemLoader
import time
# 必须要用相对路径导入，否则非同目录的外部文件导入本文件后，会导致wechat_notify无法导入而导致报错
from .wechat_notify import WeChat
from IPy import IP
import logging

urllib3.disable_warnings()
logger = logging.getLogger('Elastic.NsfocusAPI')


def _try_send_get_request(ip, url, header, cookie, timeout=6):
    """
    这个方法用于发送request.get请求，并记录发送请求的过程日志，在2024年02月29日发现当IPS的CPU占用过高时，request请求会超时，
    这个方法可以重新发送request请求并修改超时时间为10秒。
    :param ip: 向其发送request请求的IP
    :param url: 向其发送request请求的url
    :param header: http的头部
    :param cookie: 发送的request请求需要携带cookie
    :param timeout: 默认request请求的超时时间为4秒
    :return:
    """
    try:
        logger.info('%s向%s发送get请求', ip, url)
        requests_result = requests.get(url,
                                       headers=header,
                                       cookies=cookie,
                                       verify=False,
                                       timeout=timeout
                                       )
        logger.info('%s成功收到%s的响应', ip, url)
        return requests_result
    except requests.exceptions.ReadTimeout:
        logger.error('%s向%s发送get请求失败，失败原因为ReadTimeout', ip, url, exc_info=True)
        # 如果request请求超时，会再次进行尝试，并修改超时时间为10秒
        try:
            logger.info('%s再次向%s发送get请求，修改requests.get的超时时间为10秒', ip, url)
            requests_result = requests.get(url,
                                           headers=header,
                                           cookies=cookie,
                                           verify=False,
                                           timeout=10
                                           )
            logger.info('%s成功收到%s的响应', ip, url)
            return requests_result
        except requests.exceptions.ReadTimeout:
            logger.error('%s再次向%s发送get请求失败，失败原因为ReadTimeout，不再继续尝试', ip, url, exc_info=True)
    except requests.exceptions.ChunkedEncodingError:
        logger.error('%s向%s发送get请求失败，失败原因为requests.exceptions.ChunkedEncodingError', ip, url, exc_info=True)
        # 如果request请求超时，会再次进行尝试，并修改超时时间为10秒
        try:
            logger.info('%s再次向%s发送get请求，修改requests.get的超时时间为10秒', ip, url)
            requests_result = requests.get(url,
                                           headers=header,
                                           cookies=cookie,
                                           verify=False,
                                           timeout=10
                                           )
            logger.info('%s成功收到%s的响应', ip, url)
            return requests_result
        except requests.exceptions.ChunkedEncodingError:
            logger.error('%s再次向%s发送get请求失败，失败原因为requests.exceptions.ChunkedEncodingError，不再继续尝试',
                         ip, url, exc_info=True)
    except:
        logger.error('%s向%s发送get请求失败', ip, url, exc_info=True)


class NsfocusAPI:
    def __init__(self, usename, pwd, pagesize=2000, pageno=1):
        """
        :param usename: 用于登录IPS的用户名
        :param pwd: 用于登录IPS时的密码
        :param pagesize: 每页显示的记录数量，这个一般用在取IPS日志的，我们这里不太会出现大于1000条记录的情况
        :param pageno: 和pagesize搭配使用，用于取第几页记录的数据，由于pagesize固定为1000，一般不会有超出1000条记录的情况，所以页数固定为1
        """
        self.username = usename
        self.pwd = pwd
        self.pageSize = pagesize
        self.pageNo = pageno

        # 获取当前的时间戳，并转换为字符串格式，在后面用于计算13位时间戳用
        # self.currunttime = str(time.time())
        # 以下参数用于发送邮件时候用
        # self.mailServer = 'smtp.163.com'
        # self.mailAccount = 'kinggeorge58@163.com'
        # self.mailPWD = 'CIUJLHQYJACWYYZM'  # 163的发件人密码
        # # self.mailPWD = 'mkfnsbsrqtiobcbb'  # QQ的发件人密码
        self.blocked_ip_tbname = 'Blocked_IP_Info'
        self.mailServer = 'mail.cfsc.com.cn'
        self.mailAccount = 'wuzp@cfsc.com.cn'
        self.mailPWD = 'Systec123'  # 公司邮箱的发件人密码
        self.from_mail = 'wuzp@cfsc.com.cn'
        # 邮件格式这里一定要注意，中间可以用分号隔离开，但是最后一个用户那里不能用再有任何符号，否则会报错Falied recipients: {'': (550, b'Invalid User:')}
        # self.to_mail = 'lushi@cfsc.com.cn;wangpeng@cfsc.com.cn;wuzp@cfsc.com.cn;shenzx@cfsc.com.cn'
        self.to_mail = 'wuzp@cfsc.com.cn'
        # 私网IP
        self.private_ip = IP('10.0.0.0/8')
        # 白名单列表
        # self.whiteip_list = ['192.168.1.1', '10.168.98.100', '58.246.43.50']
        self.whiteip_list = ['192.168.1.1', '10.168.98.100', '58.246.43.50', '10.168.99.193', '10.168.99.194']
        # 存放Cookies的路径
        self.Cookies_Key_PATH = "_cookies_key.conf"
        self.Cookies_PATH = "/root/My_Centos_Python_Project/nsfocus_api/"

    def _get_key_cookie(self, dev_ip):
        """
        在和API接口交互前必须先完成设备的登陆认证，设备登陆认证成功后，会返回三个字段，用于后续与API交互的时候提供验证
        返回‘security_key’，'api_key'和cookie
        """
        # 绿盟登录认证用的URL
        url = f'https://{dev_ip}:8081/api/system/account/login/login'
        # 登录认证用post方法，在body中需要传用户名和密码
        params = f'{{"username": "{self.username}","password": "{self.pwd}","vcode": "jrae","lang": "zh_CN"}}'
        logger.debug(f'{dev_ip}发送get_key_cookie请求')
        # 通过post方法发送request请求
        resp = requests.post(url, params, verify=False)
        # 获取返回值，返回值的格式是json的，通过json.loads方法反序列为python的字典，然后通过字典中的'security_key'和'api_key'建获取值
        resp_dict = json.loads(resp.text)
        # pprint(resp_dict)
        # 获取cookie，后续的交互都需要在头部中带上cookie
        cookie = resp.cookies
        # 使用cookie.get_dict()方法将cookie转换为字典，然后再通过json.dumps()方法将字典系列为json的字符串，后续再通过json.load()
        # 将字符串反序列为字典
        cookie_dict = cookie.get_dict()
        cookie_json = json.dumps(cookie_dict)
        # pprint(cookie_json)
        logger.debug(f'{dev_ip}成功获得cookie')
        return resp_dict['data']['security_key'], resp_dict['data']['api_key'], cookie_json

    def _save_key_cookie(self, dev_ip):
        """
        将获取到的‘security_key’，'api_key'和cookie保存到本地
        """
        currunttime = str(time.time())
        with open(self.Cookies_PATH + dev_ip + self.Cookies_Key_PATH, "w") as f:
            security_key, api_key, cookie_json = self._get_key_cookie(dev_ip)
            # 保存获取时间以及access_token
            logger.info(f'{dev_ip}将当前时间,security_key, api_key, cookie写入本地文件')
            f.write("&".join([currunttime, str(security_key), str(api_key), cookie_json]))
        return security_key, api_key, cookie_json

    def get_key(self, dev_ip):
        try:
            with open(self.Cookies_PATH + dev_ip + self.Cookies_Key_PATH, "r") as f:
                t, security_key, api_key, cookie = f.read().split("&")
                # logger.info(f'self.currunttime的时间：{self.currunttime},当前时间：{t}')
                # 判断Cookies是否有效,Cookies的有效时间
                if 0 < time.time() - float(t) < 70:
                    logger.info(f'{dev_ip}的cookie未超时调用本地文件中security_key, api_key, cookie')
                    return security_key, api_key, cookie
                else:
                    logger.info(f'{dev_ip}本地文件中的cookie已超时，重新发起请求获取cookie')
                    return self._save_key_cookie(dev_ip)
        except:
            logger.error('%s打开本地文件失败，调用_save_key_cookie方法获取cookie', dev_ip, exc_info=True)
            return self._save_key_cookie(dev_ip)

    def calculate_time(self):
        """
        计算时间，将1683527912.4615455这种格式的时间戳转换为13位格式，在后续的request请求中需要用到
        :return:
        """
        result = re.split(r'\.', str(time.time()))
        time_13 = result[0] + result[1][:3]  # time = '1640330445060'  时间是13位格式
        return time_13

    def send_get_request(self, ip, api_url, para=''):
        """
        绿盟所有的GET方式的API都是通过这个方法发送的
        :param ip: 设备IP
        :param api_url: api接口的URL
        :param para: get请求的api接口的参数是通过para来传给IPS的
        :return: get请求的结果
        """
        # 在与API接口交互之前，收先要与设备完成认证，并获取security_key、api_key和cookie用于后续的认证
        security_key, api_key, saved_cookie_json = self.get_key(ip)
        saved_cookie_dict = json.loads(saved_cookie_json)
        # 通过下面的方法可以将json反序列话后的字典,重新变为cookie对象
        cookie = RequestsCookieJar()
        for key, value in saved_cookie_dict.items():
            cookie.set(key, value)
        # 计算13位时间戳
        time_13 = self.calculate_time()
        # api接口url
        request_api_row = api_url
        # url和api接口的参数
        request_api = api_url + para
        url = f'https://{ip}:8081{request_api}'
        # 将security-key api-key 13位时间戳 和api接口url（不带参数）合在一起做哈希
        jm = 'security-key:%s;api-key:%s;time:%s;rest-uri:%s' % (security_key, api_key, time_13, request_api_row)
        m1 = hashlib.sha256(jm.encode("utf-8"))
        sign = m1.hexdigest()
        # 绿盟的get请求需要在http头部中添加sign即哈希信息、apikey和13位时间戳
        header = {
            "sign": sign,
            "apikey": api_key,
            "time": time_13,
        }
        # 通过get方法发送request请求，需要带上之前构造的header和cookies
        logger.info('%s开始向%s发送get请求', ip, url)
        get_req_result = _try_send_get_request(ip, url, header, cookie)
        # 通过json.loads反序列化获得结果
        # rsp_get_content = json.loads(get_req_result.content)
        try:
            # 如果接收的是json的数据格式，可以直接调用request的json方法将数据进行解码
            rsp_get_content = get_req_result.json()
            return rsp_get_content
        except:
            logger.error('%s接收request返回值，json解码失败', ip, exc_info=True)
            # print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            # pprint(json.loads(get_req_result.content))

    def structure_post_url(self, ip, api_url):
        """
        绿盟的post方式的api接口都需要在url中包含sign=XX&apikey=XX&time=XX，这个方法是用来构造post请求的url
        :param ip: 设备的IP
        :param api_url: post请求的api接口地址
        :return: post请求的url
        """
        # 在与API接口交互之前，收先要与设备完成认证，并获取security_key、api_key和cookie用于后续的认证
        security_key, api_key, saved_cookie_json = self.get_key(ip)
        saved_cookie_dict = json.loads(saved_cookie_json)
        cookie = RequestsCookieJar()
        for key, value in saved_cookie_dict.items():
            cookie.set(key, value)
        # 计算13位时间戳
        time_13 = self.calculate_time()
        url = f'https://{ip}:8081{api_url}'
        jm = f'security-key:{security_key};api-key:{api_key};time:{time_13};rest-uri:{api_url}'
        m1 = hashlib.sha256(jm.encode("utf-8"))
        sign = m1.hexdigest()
        # 构造POST请求的URL
        url_request = f'{url}?sign={sign}&apikey={api_key}&time={time_13}'
        logger.debug(f'{ip}调用structure_post_url构造{url_request}')
        return url_request, cookie

    def post_blacklist(self, ip, blackip, days=30):
        # 加黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        data = {
            "action": "insert",
            "data": {'abstract': f'于{current_time}添加',  # 备注信息
                     'cate': 'ip',  # 通过IP的方式添加
                     'direction': '3',  # 不管是黑名单是以源地址还会目的地址，都禁止通信
                     'enabled': 'true',
                     'end_time': end_time.strftime("%Y.%m.%d"),
                     'name': blackip,
                     'start_time': '',  # 不写默认就是当前时间
                     'threat_type': '9'
                     }
        }
        # 发送请求
        try:
            logger.info(f'{ip}调用post_blacklist方法向{url_request}提交黑名单')
            request = requests.post(url=url_request, data=json.dumps(data), cookies=cookie, verify=False, timeout=4)
            return True, request.text
        except requests.exceptions.ConnectTimeout as e:
            logger.error('%s提交黑名单超时', ip, exc_info=True)
            # print('请求失败', e)
            return False, e
        except Exception as e:
            logger.error('%s提交黑名单失败', ip, exc_info=True)
            # print('请求失败', e)
            return False, e

    def post_blacklist_many(self, ip, blackip, expired_blackdict, location, days=30):
        # 加黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # 格式化当前时间
        current_time_strf = current_time.strftime("%Y-%m-%d %H:%M:%S")
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        # 模板的位置；这里用到jinja2的模板，这个模板主要是为发送的邮件内容提供模板
        env = Environment(loader=FileSystemLoader('.'))
        # 加载模板
        wx_template = env.get_template("wechat_notice.j2")
        # 创建wx对象
        wx = WeChat()

        for attack_ip, country, event in blackip:
            # 如果攻击attack_ip在expired_blackdict中，则需要调用更新update_ips_blacklist方法
            if attack_ip in expired_blackdict.keys():
                self.update_ips_blacklist(ip, attack_ip, expired_blackdict[attack_ip])
            else:
                data = {
                    "action": "insert",
                    "data": {'abstract': f'于{current_time_strf}批量添加',  # 备注信息
                             'cate': 'ip',  # 通过IP的方式添加
                             'direction': '3',  # 不管是黑名单是以源地址还会目的地址，都禁止通信
                             'enabled': 'true',
                             # 必须是这个"%Y.%m.%d"格式，我之前用"%Y-%m-%d"这种格式会有BUG，妈的害我查了好久
                             'end_time': end_time.strftime("%Y.%m.%d"),
                             'name': attack_ip,
                             'start_time': '',  # 不写默认就是当前时间
                             'threat_type': '9'
                             }
                }
                # 发送请求
                try:
                    logger.info(f'{ip}调用post_blacklist_many方法批量提交黑名单')
                    request = requests.post(url=url_request, data=json.dumps(data), cookies=cookie,
                                            verify=False, timeout=4)
                    # logger.info(f'{ip}批量提交黑名单成功，{request.text}')
                    # print(request.text)
                except requests.exceptions.ConnectTimeout as e:
                    logger.error('%s批量提交黑名单失败', ip, exc_info=True)
                    # print('请求失败', e)
            # 通过J2构造需要发送的告警模板
            wx_result = wx_template.render(IP=attack_ip, c_time=current_time_strf, location=location,
                                           country=country, event=event)
            # print(wx_result)
            # 使用微信的send_markdown方法将jinja2生成的markdown语句发送出去
            logger.info('%s发送企业微信告警', ip)
            wx.send_markdown(wx_result)

    def post_applyconfig(self, ip):
        """
        绿盟的设备在post配置后，必须要应用配置，这个方法就是相当于页面上的应用配置
        :param ip: IPS的设备IP
        :return:
        """
        # 应用配置的API接口
        url = '/api/index/applyconfig'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 应用配置的post请求只要有了URL和cookie就可以了
        try:
            logger.info(f'{ip}提交应用配置')
            applyconfig_post = requests.post(url=url_request, cookies=cookie, verify=False, timeout=4)
            return True, applyconfig_post.text
        except requests.exceptions.ConnectTimeout as e:
            logger.error('%s提交应用配置超时', ip, exc_info=True)
            # print('请求失败', e)
            return False, e
        except Exception as e:
            logger.error('%s提交应用配置失败', ip, exc_info=True)
            # print('请求失败', e)
            return False, e

    def get_ips_event(self, ip, time_range):
        """
        本方法用于获取IPS的网络入侵日志
        :param ip: IPS的设备ip
        :param time_range: 想要获取的IPS日志的时间范围，单位是小时，即获取当前时间往前time_range小时的IPS日志
        :return:返回网络入侵日志和当前时间
        """
        # 获得timedelta用于计算时间
        hour_step = datetime.timedelta(hours=time_range)
        # 当前时间，即IPS日志的结束时间 时间格式为2023-05-09 15:06:03.883005
        e_datetime = datetime.datetime.now()
        # IPS日志的起始时间 时间格式为2023-05-09 15:06:03.883005
        s_datetime = e_datetime - hour_step

        # 将2023-05-09 15:06:03.883005格式时间转换为时间戳，这个时间戳需要放在get请求中
        e_time = int(datetime.datetime.timestamp(e_datetime))
        s_time = int(datetime.datetime.timestamp(s_datetime))

        # 获取ips网络入侵日志的api接口
        api = '/api/log/security/ips/event'
        # 获取ips网络入侵日志的api接口的参数
        api_para = f'?pageSize={self.pageSize}&pageNo={self.pageNo}&s_time={s_time}&e_time={e_time}'
        # 通过self.send_get_request方法发送request请求，并获取结果
        logger.info(f'{ip}获取IPS日志')
        result = self.send_get_request(ip, api, api_para)
        # return result["data"]['data']
        return result, e_datetime

    def get_ips_blacklist(self, ip):
        """
        本方法用于获取ips的黑名单信息
        :param ip: IPS地址
        :return: 返回有效期内黑名单信息和不在有效期内的IP
        """
        logger.info('%s开始执行get_ips_blacklist方法', ip)
        # 获取ips黑名单的api接口
        api = '/api/policy/globalList/black/manual'
        # 获取ips黑名单的api接口的参数
        api_para = f'?pageSize={self.pageSize}&pageNo={self.pageNo}'
        # 通过self.send_get_request方法发送request请求，并获取结果
        logger.info(f'{ip}获取IPS黑名单列表')
        result = self.send_get_request(ip, api, api_para)
        valid_backlist = []
        expired_blackdict = dict()

        # 这个方法是将'2023.08.07'这种时间格式的字符串，最终以'2023.8.7'传递给datatime，因为datatime只能传入整数，08不能传入
        def format_date(item):
            if item[0] == '0':
                item = item[1]
            return int(item)

        for i in result['data']['data']:
            end_time = i['end_time']
            backip = i['name']
            backip_id = i['id']
            # 如果黑名单的有效期是永久，则直接加入valid_backlist
            if end_time == '':
                valid_backlist.append((backip, backip_id))
                continue
            # 将时间'2023.08.10'进行分列，分别获取年、月、日
            re_sult = re.split(r'\.', end_time)
            year = int(re_sult[0])
            month = format_date(re_sult[1])
            day = format_date(re_sult[2])
            # 获取今天的年、月、日
            today = datetime.datetime.today()
            today_year = today.year
            today_month = today.month
            today_day = today.day
            # 计算是否黑名单的已过期
            interval = datetime.datetime(year, month, day) - datetime.datetime(today_year, today_month, today_day)
            if int(interval.days) > 0:
                valid_backlist.append((backip, backip_id))
            else:
                expired_blackdict[backip] = backip_id
        return valid_backlist, expired_blackdict

    # def get_ips_session(self, ip):
    #     """
    #     本方法用于获取IPS最近一小时的会话信息,数据格式如下，并通过numpy计算最近5分钟的会话平均数
    #         [{'count': 168, 'time': '09:53'},
    #          {'count': 164, 'time': '09:55'},
    #          {'count': 166, 'time': '09:56'},
    #          {'count': 159, 'time': '09:57'},
    #          {'count': 154, 'time': '09:58'},
    #          {'count': 171, 'time': '09:59'},
    #          {'count': 151, 'time': '10:00'},
    #         ]
    #     :param ip: IPS的设备ip
    #     :return:会话平均数
    #     """
    #     # 获取ips网络入侵日志的api接口
    #     api = '/api/dashboards/system/concurrentSess'
    #     # 获取ips会话信息的api接口的参数
    #     api_para = f'?period=1'
    #     # 通过self.send_get_request方法发送request请求，并获取结果
    #     logger.info(f'{ip}获取IPS会话信息')
    #     result = self.send_get_request(ip, api, api_para)
    #     # 得到的结果的类型为{'count': 168, 'time': '09:53'}，需要计算最近五分钟的平均会话数，利用[-5:]来获取
    #     avg_list = np.array([i['count'] for i in result['data']][-5:])
    #     # 用numpy来计算平均值
    #     avg = avg_list.mean()
    #     # 对计算结果取整，并返回判断结果
    #     return int(avg), avg < 500

    def delete_blacklist(self, ip):
        """
        删除过期的黑名单IP
        :param ip:设备IP
        :return:
        """
        # 加黑名单的API接口
        logger.info('%s调用get_ips_blacklist方法，获取超时的黑名单IP信息', ip)
        valid_backlist, expired_blackdict = self.get_ips_blacklist(ip)
        blacklist = [str(i) for i in expired_blackdict.values()]
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        data = {
            "action": "delete",
            "data": blacklist
        }
        # 发送请求
        try:
            logger.info('%s发送delete_blacklist的post请求', ip)
            result = requests.post(url=url_request, data=json.dumps(data), cookies=cookie, verify=False, timeout=4)
            # requests返回的json数据需要loads回去才可以通过python的字典操作
            result_dict = json.loads(result.text)
            res_status = result_dict.get("message", "Fail")
            if res_status == 'Success':
                apply_result, apply_content = self.post_applyconfig(ip)
                # pprint(apply_content)
                return True, result_dict
            else:
                return False, result_dict
        except requests.exceptions.ConnectTimeout as e:
            logger.error('%s delete_blacklist方法提交requests请求超时', ip, exc_info=True)
            return False, e

    def update_ips_blacklist(self, ip, blackip, blackip_id, days=90):
        # black_id用于存储黑名单列表中的id，在更新黑名单列表的时候，需要用id来标识需要更新的信息
        # black_id = 0
        # 调用get_ips_blacklist()函数，用来获得所有的黑名单信息
        # blacklist = self.get_ips_blacklist(ip)
        # for dict_info in blacklist:
        #     for k, v in dict_info.items():
        #         # 通过blackip定位到具体的黑名单信息
        #         if v == blackip:
        #             # 然后通过id键获得需要的id值
        #             black_id = dict_info['id']
        # 更新黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        data = {
            "action": "update",
            "data": {
                'id': blackip_id,
                'abstract': f'于{current_time}更新',  # 备注信息
                'cate': 'ip',  # 通过IP的方式添加
                'end_time': end_time.strftime("%Y.%m.%d"),
                'name': blackip,
                'start_time': '',  # 不写默认就是当前时间
                'threat_type': '9'
            }
        }
        # 发送请求
        try:
            request = requests.post(url=url_request, data=json.dumps(data), cookies=cookie, verify=False, timeout=4)
            logger.info('%s提交update_ips_blacklist的requests.post请求成功', ip)
            return True, request.text
        except requests.exceptions.ConnectTimeout as e:
            logger.error('%s提交update_ips_blacklist的requests.post请求失败', ip, exc_info=True)
            return False, e

    def send_mail(self, subj, main_body, files=None):  # 使用SSL加密SMTP发送邮件, 此函数发送的邮件有主题,有正文,还可以发送附件
        """
        本方法用于发送邮件用
        :param subj: 邮件的主题
        :param main_body: 邮件的内容
        :param files: 附件
        :return: 返回邮件发送的状态信息
        """
        tos = self.to_mail.split(';')  # 把多个邮件接受者通过';'分开
        date = email.utils.formatdate()  # 格式化邮件时间
        msg = MIMEMultipart()  # 产生MIME多部分的邮件信息
        msg["Subject"] = subj  # 主题
        msg["From"] = formataddr(["绿盟IPS自动化告警", self.from_mail])  # 发件人
        msg["To"] = self.to_mail  # 收件人
        msg["Date"] = date  # 发件日期

        # # 指定图片为当前目录
        # fp = open('30year.gif', 'rb')
        # msgImage = MIMEImage(fp.read())
        # fp.close()
        # # 定义图片 ID，在 HTML 文本中引用
        # msgImage.add_header('Content-ID', '<image>')
        # msg.attach(msgImage)

        # 邮件正文为Text类型, 使用MIMEText添加
        # MIME类型介绍 https://docs.python.org/2/library/email.mime.html
        part = MIMEText(main_body, 'html')
        msg.attach(part)  # 添加正文

        if files:  # 如果存在附件文件
            for file in files:  # 逐个读取文件,并添加到附件
                # MIMEXXX决定了什么类型 MIMEApplication为二进制文件
                # 添加二进制文件
                part = MIMEApplication(open(file, 'rb').read())
                # 添加头部信息, 说明此文件为附件,并且添加文件名
                part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
                # 把这个部分内容添加到MIMEMultipart()中
                msg.attach(part)

        server = smtplib.SMTP_SSL(self.mailServer, 465)  # 连接邮件服务器
        server.login(self.mailAccount, self.mailPWD)  # 通过用户名和密码登录邮件服务器
        failed = server.sendmail(self.from_mail, tos, msg.as_string())  # 发送邮件
        server.quit()  # 退出会话
        if failed:
            print('Falied recipients:', failed)  # 如果出现故障，打印故障原因！
        else:
            print('邮件已经成功发出！')  # 如果没有故障发生，打印'邮件已经成功发出！'！

    def private_ip_determine(self, determine_ip):
        if determine_ip in self.private_ip:
            return True
        else:
            return False


class NsfocusAPIv2(NsfocusAPI):
    def get_ips_event(self, ip, time_range):
        """
        本方法用于获取IPS的网络入侵日志
        :param ip: IPS的设备ip
        :param time_range: 想要获取的IPS日志的时间范围，单位是小时，即获取当前时间往前time_range小时的IPS日志
        :return:返回网络入侵日志和当前时间
        """
        # 获得timedelta用于计算时间
        hour_step = datetime.timedelta(hours=time_range)
        # 当前时间，即IPS日志的结束时间 时间格式为2023-05-09 15:06:03.883005
        e_datetime = datetime.datetime.now()
        # IPS日志的起始时间 时间格式为2023-05-09 15:06:03.883005
        s_datetime = e_datetime - hour_step

        # 将2023-05-09 15:06:03.883005格式时间转换为时间戳，这个时间戳需要放在get请求中
        e_time = int(datetime.datetime.timestamp(e_datetime))
        s_time = int(datetime.datetime.timestamp(s_datetime))

        pageSize = 20
        pageNo = ''
        # 获取ips网络入侵日志的api接口
        api = '/api/log/security/ips/event'
        # 获取ips网络入侵日志的api接口的参数
        api_para = f'?pageSize={pageSize}&pageNo={pageNo}&s_time={s_time}&e_time={e_time}'
        # 通过self.send_get_request方法发送request请求，并获取结果
        logger.info(f'{ip}获取IPS日志')
        result = self.send_get_request(ip, api, api_para)
        # return result["data"]['data']
        return result, e_datetime

    def manual_post_blacklist_many(self, ip, blackip, days=30):
        # 加黑名单的API接口
        url = '/api/policy/globalList/black/manual'
        # 通过structure_post_url方法，构造URL
        url_request, cookie = self.structure_post_url(ip, url)
        # 获取当前时间，用于给黑名单的abstract属性设置时间，abstract属性在IPS页面中就是备注
        current_time = datetime.datetime.now()
        # 格式化当前时间
        current_time_strf = current_time.strftime("%Y-%m-%d %H:%M:%S")
        # end_time是黑名单的封禁时间默认加黑30天
        end_time = current_time + datetime.timedelta(days=days)
        v, e = self.get_ips_blacklist(ip)
        valid_list = [i[0] for i in v]
        expired_list = e.keys()

        for attack_ip in blackip:
            if attack_ip in valid_list:
                logger.info(f'{ip}攻击IP{attack_ip}已在黑名单列表中')
                continue
            # 如果攻击attack_ip在expired_blackdict中，则需要调用更新update_ips_blacklist方法
            if attack_ip in expired_list:
                logger.info(f'{ip}攻击IP{attack_ip}在黑名单列表中，但是超过了时间有效期，执行更新操作')
                self.update_ips_blacklist(ip, attack_ip, e[attack_ip])
            else:
                data = {
                    "action": "insert",
                    "data": {'abstract': f'于{current_time_strf}批量添加WAF',  # 备注信息
                             'cate': 'ip',  # 通过IP的方式添加
                             'direction': '3',  # 不管是黑名单是以源地址还会目的地址，都禁止通信
                             'enabled': 'true',
                             # 必须是这个"%Y.%m.%d"格式，我之前用"%Y-%m-%d"这种格式会有BUG，妈的害我查了好久
                             'end_time': end_time.strftime("%Y.%m.%d"),
                             'name': attack_ip,
                             'start_time': '',  # 不写默认就是当前时间
                             'threat_type': '9'
                             }
                }
                # 发送请求
                try:
                    logger.info(f'{ip}调用post_blacklist_many方法批量提交黑名单')
                    requests.post(url=url_request, data=json.dumps(data), cookies=cookie,
                                  verify=False, timeout=4)
                    logger.info(f'{ip}提交黑名单{attack_ip}成功')
                    # print(request.text)
                except requests.exceptions.ConnectTimeout:
                    logger.error('%s批量提交黑名单超时', ip, exc_info=True)
                except:
                    logger.error('%s批量提交黑名单失败', ip, exc_info=True)
        # 一定要记得应用配置
        self.post_applyconfig(ip)


if __name__ == '__main__':
    login_account = 'wuzp'
    loging_password = '6dd3cda8f68bc2b6701ba3e4e83800991ad02be83419af8cc500e20d93432e5c14f345139d273' \
                      '08b9f6ffb5c2d17ebc2f578d4798ba066e9970038a3f055a8b504538696491a6bffce9f1330698974d7' \
                      'd417eeb85f6fd21c86e663e4ea8eae91f0387dc4b2de19edb1c4979b1b31a61c3fe82c9546efb1a50f2956b' \
                      '8bd10fc39074dda3a7b6cd0902f4c5db4fa18a17d11d6cfe7f8a4524dfa78f5cc8c3a19972010a06bf1995c076' \
                      'ab0b01856aed8e189286f19447aab53b1dd4103296e249d74b9d21f27e043045757fcf56bb67a57c343435a2f374' \
                      'd265477634f704feeb744e2c7ea77c28dd35bebe0fb156910ef6519c15513644bc92f495fe5541f4077'

    #
    myobj = NsfocusAPI(login_account, loging_password)
    # myobj = NsfocusAPIv2(login_account, loging_password)
    # ['10.168.46.33', 'JQ_BlockScan_INT', '金桥网上交易区'],
    # myobj.analyse_scan('10.168.46.33', 'JQ_BlockScan_INT', '金桥网上交易区')
    # security_key, api_key, cookie = myobj.get_keys("10.168.224.241")
    # print(security_key)
    # print(api_key)
    # print(cookie)

    # valid_backlist, expired_blackdict = myobj.get_ips_blacklist("10.192.4.61")
    # print(valid_backlist)
    # print(expired_blackdict)
    # bl = ['100026', '150114']
    # status, res = myobj.delete_blacklist("10.167.68.9")
    # print(status)
    # print('-------------')
    # print(res)
    # result, t = myobj.get_ips_event('10.168.224.241', 1)
    # pprint(result)
    # print(len(result['data']['data']))
    # ['10.192.4.61', 'KJW_BlockScan_first', '科技网一期'],
    # myobj.analyse_scan('10.192.4.61', 'KJW_BlockScan_first', '科技网一期')
    # x = True if "103.178.237.244" in [i[0] for i in valid_backlist] else False
    # x = True if "103.178.237.244" in [i for i in expired_blackdict.keys()] else False
    # pprint([i for i in expired_blackdict.keys()])
    # print(x)
    v, e = myobj.get_ips_blacklist('10.192.4.61')

    pprint(v)
