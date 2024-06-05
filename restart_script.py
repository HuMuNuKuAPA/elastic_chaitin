#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import os


# 获得PID
cmd = 'pgrep -f entrance.py'
pid = os.popen(cmd).read()
cmd = f"kill {pid}"
os.system(cmd)
# cmd = 'nohup python3.11 -u  scheduler_AddBlackIP.py > Add_Black_IP.log 2>&1 &'
# 不记录运行时产生的日志
cmd = 'nohup python3.11 -u entrance.py > /dev/null 2>&1 &'
os.system(cmd)
print("Seccessfully restart the script")