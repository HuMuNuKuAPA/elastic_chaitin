#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import os

# cmd = 'nohup python3.11 -u  entrance.py > elastic_chaitin.log 2>&1 &'
# 不记录运行时产生的日志
cmd = 'nohup python3.11 -u entrance.py > /dev/null 2>&1 &'
os.system(cmd)
print("Seccessfully start the script")
