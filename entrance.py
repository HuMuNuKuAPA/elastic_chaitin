#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import logging
import sys
from logging.handlers import TimedRotatingFileHandler
import os
import time
from analyze_ChaiTin import ELKChaiTin
from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime, timedelta


class MyTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, dir_name, when, interval, backupCount=0, encoding=None, delay=False, utc=False, atTime=None):
        self.dir_name = dir_name
        self.prefix = "Elastic"
        filename = self._get_filename()
        super().__init__(filename, when, interval, backupCount, encoding, delay, utc, atTime)

    def _get_filename(self):
        return os.path.join(self.dir_name, f"{self.prefix}_{time.strftime('%Y-%m-%d')}")

    def doRollover(self):
        """
        doRollover is called whenever the current log file needs to be rolled over to a new file.
        This method adjusts the filename based on the current date before performing the rollover,
        ensuring that each new log file has a unique name that includes the date.
        """
        self.stream.close()
        # Get the current time and format it for the filename
        currentTime = int(time.time())
        dfn = self.rotation_filename(
            self._get_filename() + "." + time.strftime(self.suffix, time.localtime(currentTime)))
        self.baseFilename = dfn
        self.mode = 'a'
        self.stream = self._open()


# current_time = time.strftime("%Y-%m-%d", time.localtime())
logger = logging.getLogger("Elastic")
logger.setLevel(level=logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s',
                              datefmt='%Y/%m/%d %H:%M:%S')

# StreamHandler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(level=logging.DEBUG)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# TimedRotatingFileHandler with specified path
log_file_path = '/root/My_Centos_Python_Project/elastic_test/logdir'  # 指定日志文件的路径
file_handler = MyTimedRotatingFileHandler(log_file_path, when='midnight', interval=1, backupCount=7, encoding='utf-8')
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


def main():
    ct = datetime.now()
    ctf = ct.strftime('%Y-%m-%d %H:%M:%S')
    st = (ct - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    myobj = ELKChaiTin(st, ctf)
    myobj.start_judging()
    # myobj.manual_judgment()
    # _l = ["2.2.2.2","1.1.1.1"]
    # myobj.exist_in_manual_index(_l)
    # myobj.send_to_ips()
    # myobj.refresh_expired()
    # aa = myobj.agg_attack_ip()
    # print(aa)
    # sql_injection('222.67.134.132', '2024-04-29 10:00:00')
    # info_leak('47.96.91.95', '2024-04-28 00:00:00')
    # myobj.xss('22.67.134.132')
    # xxe('217.148.142.19', '2024-04-15 00:00:00')
    # ssrf('222.65.128.137', '2024-04-13 00:00:00')
    # ssrf('163.125.197.202', '2024-05-06 00:00:00')
    # permission_bypass('222.65.128.137', '2024-04-13 00:00:00')
    # myobj.file_upload("113.128.82.219")
    # myobj.file_upload("11.128.82.219")
    # ssti("217.148.142.19", '2024-04-22 00:00:00')
    # ssti("139.227.221.146", '2024-05-07 00:00:00')
    # directory_traversal("123.132.43.133", "2024-05-01 00:00:00")
    # myobj.file_inclusion("150.129.216.206")
    # myobj.file_inclusion("120.244.236.71")
    # myobj.shanghai_net_detect('123.132.43.133')
    # myobj.shanghai_net_detect('114.86.94.216')


# main()

# create scheduler object
scheduler = BlockingScheduler(timezone='Asia/Shanghai')
# schedule function to run every hour
scheduler.add_job(main, 'interval', seconds=30)
# start scheduler
scheduler.start()
"""
nohup python3.11 -u entrance.py > /dev/null 2>&1 &
nohup: 确保命令在用户退出终端后继续运行。
python3.11 -u entrance.py: 运行Python 3.11解释器，并执行脚本 entrance.py，其中 -u 选项确保输出是不缓存的。
> /dev/null: 将标准输出（stdout）重定向到 /dev/null，即丢弃所有输出。
2>&1: 将标准错误（stderr）重定向到标准输出（stdout），也即丢弃所有错误信息。
&: 将命令放入后台执行。
"""