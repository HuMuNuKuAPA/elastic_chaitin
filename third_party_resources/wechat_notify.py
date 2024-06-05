#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import os
import requests
import time
import json
# from requests_toolbelt import MultipartEncoder


class WeChat:
    def __init__(self):
        """
        配置初始信息
        """
        self.CORPID = "wwb3dae7756949756d"  # 企业ID
        self.CORPSECRET = "_79y4KQEOjwPd_w1bn85q6Bv_V35qP_hDY487gz469M"  # 应用Secret
        self.AGENTID = "1000042"  # 应用Agentid
        # self.TOUSER = "WuZhiPing|ShenZhiXin|ShiZiBing|WangPeng01"  # 接收消息的userid
        # self.TOUSER = "WuZhiPing"  # 接收消息的userid
        # 沈智欣：005059  陆适：000226 王鹏：000260
        # self.TOUSER = "004453|005059|000226|000260"  # 接收消息的userid
        self.TOUSER = "004453"  # 接收消息的userid
        self.ACCESS_TOKEN_PATH = "access_token.conf"  # 存放access_token的路径

    def _get_access_token(self):
        """
        调用接口返回登录信息access_token
        """
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={self.CORPID}&corpsecret={self.CORPSECRET}"
        res = requests.get(url=url)
        return json.loads(res.text)['access_token']

    def _save_access_token(self, cur_time):
        """
        将获取到的access_token保存到本地
        """
        with open(self.ACCESS_TOKEN_PATH, "w") as f:
            access_token = self._get_access_token()
            # 保存获取时间以及access_token
            f.write("\t".join([str(cur_time), access_token]))
        return access_token

    def get_access_token(self):
        cur_time = time.time()
        try:
            with open(self.ACCESS_TOKEN_PATH, "r") as f:
                t, access_token = f.read().split()
                # 判断access_token是否有效
                if 0 < cur_time - float(t) < 7200:
                    return access_token
                else:
                    return self._save_access_token(cur_time)
        except:
            return self._save_access_token(cur_time)

    def send_message(self, message):
        """
        发送文本消息
        """
        url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={self.get_access_token()}"
        send_values = {
            "touser": self.TOUSER,
            "msgtype": "text",
            "agentid": self.AGENTID,
            "text": {
                "content": message
            },
        }
        send_message = (bytes(json.dumps(send_values), 'utf-8'))
        res = requests.post(url, send_message)
        return res.json()['errmsg']

    def _upload_file(self, file):
        """
        先将文件上传到临时媒体库
        """
        url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={self.get_access_token()}&type=file"
        data = {"file": open(file, "rb")}
        res = requests.post(url, files=data)
        return res.json()['media_id']

    def send_file(self, file):
        """
        发送文件
        """
        media_id = self._upload_file(file)  # 先将文件上传至临时媒体库
        url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={self.get_access_token()}"
        send_values = {
            "touser": self.TOUSER,
            "msgtype": "file",
            "agentid": self.AGENTID,
            "file": {
                "media_id": media_id
            },
        }
        send_message = (bytes(json.dumps(send_values), 'utf-8'))
        res = requests.post(url, send_message)
        return res.json()['errmsg']

    def send_markdown(self, content):
        url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={self.get_access_token()}"
        send_values = {
            "touser": self.TOUSER,
            "msgtype": "markdown",
            "agentid": self.AGENTID,
            "markdown": {
                "content": content
            },
        }
        send_message = (bytes(json.dumps(send_values), 'utf-8'))
        res = requests.post(url, send_message)
        return res.json()['errmsg']

    # def upload_pic(self, file_path):
    #     url = f"https://qyapi.weixin.qq.com/cgi-bin/media/uploadimg?access_token={self.get_access_token()}"
    #     multipart_data = MultipartEncoder(
    #         fields={
    #             'file': (os.path.basename(file_path), open(file_path, 'rb'), 'image/png')
    #         }
    #     )
    #     print(multipart_data)
    #     headers = {'Content-Type': multipart_data.content_type}
    #     response = requests.post(url, data=multipart_data, headers=headers)
    #     print(response.json())
    #     return response.json()
    #
    # def send_picture(self, title, description, picurl):
    #     url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={self.get_access_token()}"
    #     send_values = {
    #         "touser": self.TOUSER,
    #         "msgtype": "news",
    #         "agentid": self.AGENTID,
    #         "news": {
    #             "articles": [
    #                 {
    #                     "title": title,
    #                     "description": description,
    #                     "url": picurl,
    #                     "picurl": picurl,
    #                     # "appid": "wx123123123123123",
    #                     # "pagepath": "pages/index?userid=zhangsan&orderid=123123123"
    #                 }
    #             ]
    #         },
    #     }
    #     send_message = (bytes(json.dumps(send_values), 'utf-8'))
    #     res = requests.post(url, send_message)
    #     return res.json()['errmsg']


if __name__ == '__main__':
    wx = WeChat()
    # 发送信息"test1"
    # swss = wx.send_message("测试消息<code>192.168.1.1</code>")
    # print(swss)
    # # # 发送文件
    # wx.send_file("交易流量速率统计_v1.0_20220222.xlsx")
    mk = """
### 从2023-06-22 08:30:06至2023-06-23 08:30:06的(24小时)之间，共监测到：\n
<font color="info"> </font>\n
>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n
<font color="info"> </font>\n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n
<font color="info"> </font>\n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n
<font color="info"> </font>\n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n
<font color="info"> </font>\n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n
\n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n \n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)；\n \n

>**攻击源IP:**`116.147.37.17`,被IPS拦截<font color="info">4</font>次\n
>**该IP触发以下IPS告警:** Zgrab 扫描攻击探测；Confluence Server and Data Center OGNL注入远程代码执行漏洞(CVE-2022-26134)312312；\n
\n
"""
    current_time = '12:10'
    location = 'JQ'
    ips_ip = '10.168.46.33'

    content = f'### {location}IPS\n>##### {current_time}_{location}IPS {ips_ip} 无威胁拦截的告警日志！'
    wx.send_markdown(content)
