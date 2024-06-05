#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
from elasticsearch import Elasticsearch, helpers, NotFoundError, BadRequestError
from elasticsearch.helpers import bulk
from pprint import pprint
import os
from urllib3 import disable_warnings
import logging
from IPy import IP
import re
from datetime import datetime, timedelta
from configparser import ConfigParser
from third_party_resources.nsfocus_restfulapi import NsfocusAPIv2
from third_party_resources.wechat_notify import WeChat
from jinja2 import Environment, FileSystemLoader

disable_warnings()
logger = logging.getLogger('Elastic.AnalyzeChaiTin')


class ELKChaiTin:
    def __init__(self, search_time, current_time):
        self.search_time = search_time
        self.current_time = current_time
        # self._elastic_host = os.getenv('elastic_host')
        # self._elastic_user = os.getenv('elastic_user')
        # self._elastic_pwd = os.getenv('elastic_pwd')
        self._block_dict = dict()
        self._expired_ip = []
        self._manual = dict()
        # 读取配置文件中的登录信息和IP地址
        _config = ConfigParser()
        _config.read('config.ini')  # 假设配置文件名为config.ini
        self._elastic_host = _config.get('Elastic', 'host')
        self._elastic_user = _config.get('Elastic', 'user')
        self._elastic_pwd = _config.get('Elastic', 'pwd')
        self._login_account = _config.get('Login', 'account')
        self._loging_password = _config.get('Login', 'password')
        self._target_ips = [
            _config.get('Targets', 'jq'),
            _config.get('Targets', 'kjw'),
            _config.get('Targets', 'kjw2'),
            _config.get('Targets', 'oa')
        ]
        self._es = Elasticsearch(hosts=self._elastic_host,
                                 basic_auth=(self._elastic_user, self._elastic_pwd),
                                 # ca_certs='http_ca.crt',
                                 verify_certs=False)
        self._event_mapping = {
            2: "利用了超过三种不同类型的攻击方式进行攻击",
            3: "攻击了多个目标并且使用了多种类型的攻击方式",
            "sql_injection": "因触发[SQL注入]告警",
            "info_leak": "因触发[信息泄露]告警，并且在urlpath中发现了预定义的敏感词",
            "xss": "触发[XSS]告警，因为http body体中的载荷含有触发了高危的代码或触发了告警的载荷位于http的头部字段",
            "xxe": "触发[XXE]告警，因为http body体中的载荷含有file or http关键字",
            "ssrf": "触发[SSRF]告警，并且使用了多种攻击手段触发了多个不同类型的SSRF告警",
            "permission_bypass": "触发了[权限绕过]告警，触发了告警的载荷部分包含CVE攻击",
            "file_inclusion": "触发了[文件包含]告警，触发了告警的载荷部分包含有预定义的敏感词",
            "file_upload": "触发了[文件上传]告警，上传的文件中含有注入行为的代码",
            "ssti": "触发了[ssti]告警，触发了告警的载荷位于urlpath或http的头部字段",
            "directory_traversal": "触发了[目录穿越]告警，在url中发现了2个以上的路径遍历符号",
        }
        # 将攻击类型与处理函数映射为字典，提高可维护性
        self._attack_handlers = {
            'sql_injection': self.sql_injection,
            'info_leak': self.info_leak,
            'xss': self.xss,
            'xxe': self.xxe,
            'ssrf': self.ssrf,
            'permission_bypass': self.permission_bypass,
            'file_inclusion': self.file_inclusion,
            'file_upload': self.file_upload,
            'ssti': self.ssti,
            'directory_traversal': self.directory_traversal,
            # 'backdoor': self.backdoor  # 暂时不做这个攻击类型的判断
        }
        self._country_code = {
            "AD": "安道尔共和国",
            "AE": "阿拉伯联合酋长国",
            "AF": "阿富汗",
            "AG": "安提瓜和巴布达",
            "AI": "安圭拉岛",
            "AL": "阿尔巴尼亚",
            "AM": "亚美尼亚",
            "AO": "安哥拉",
            "AR": "阿根廷",
            "AT": "奥地利",
            "AU": "澳大利亚",
            "AZ": "阿塞拜疆",
            "BB": "巴巴多斯",
            "BD": "孟加拉国",
            "BE": "比利时",
            "BF": "布基纳法索",
            "BG": "保加利亚",
            "BH": "巴林",
            "BI": "布隆迪",
            "BJ": "贝宁",
            "BL": "巴勒斯坦",
            "BM": "百慕大群岛",
            "BN": "文莱",
            "BO": "玻利维亚",
            "BR": "巴西",
            "BS": "巴哈马",
            "BW": "博茨瓦纳",
            "BY": "白俄罗斯",
            "BZ": "伯利兹",
            "CA": "加拿大",
            "CF": "中非共和国",
            "CG": "刚果",
            "CH": "瑞士",
            "CK": "库克群岛",
            "CL": "智利",
            "CM": "喀麦隆",
            "CN": "中国",
            "CO": "哥伦比亚",
            "CR": "哥斯达黎加",
            "CS": "捷克",
            "CU": "古巴",
            "CY": "塞浦路斯",
            "CZ": "捷克",
            "DE": "德国",
            "DJ": "吉布提",
            "DK": "丹麦",
            "DO": "多米尼加共和国",
            "DZ": "阿尔及利亚",
            "EC": "厄瓜多尔",
            "EE": "爱沙尼亚",
            "EG": "埃及",
            "ES": "西班牙",
            "ET": "埃塞俄比亚",
            "FI": "芬兰",
            "FJ": "斐济",
            "FR": "法国",
            "GA": "加蓬",
            "GB": "英国",
            "GD": "格林纳达",
            "GE": "格鲁吉亚",
            "GF": "法属圭亚那",
            "GH": "加纳",
            "GI": "直布罗陀",
            "GM": "冈比亚",
            "GN": "几内亚",
            "GR": "希腊",
            "GT": "危地马拉",
            "GU": "关岛",
            "GY": "圭亚那",
            "HK": "中国香港特别行政区",
            "HN": "洪都拉斯",
            "HT": "海地",
            "HU": "匈牙利",
            "ID": "印度尼西亚",
            "IE": "爱尔兰",
            "IL": "以色列",
            "IN": "印度",
            "IQ": "伊拉克",
            "IR": "伊朗",
            "IS": "冰岛",
            "IT": "意大利",
            "JM": "牙买加",
            "JO": "约旦",
            "JP": "日本",
            "KE": "肯尼亚",
            "KG": "吉尔吉斯坦",
            "KH": "柬埔寨",
            "KP": "朝鲜",
            "KR": "韩国",
            "KT": "科特迪瓦共和国",
            "KW": "科威特",
            "KZ": "哈萨克斯坦",
            "LA": "老挝",
            "LB": "黎巴嫩",
            "LC": "圣卢西亚",
            "LI": "列支敦士登",
            "LK": "斯里兰卡",
            "LR": "利比里亚",
            "LS": "莱索托",
            "LT": "立陶宛",
            "LU": "卢森堡",
            "LV": "拉脱维亚",
            "LY": "利比亚",
            "MA": "摩洛哥",
            "MC": "摩纳哥",
            "MD": "摩尔多瓦",
            "MG": "马达加斯加",
            "ML": "马里",
            "MM": "缅甸",
            "MN": "蒙古",
            "MO": "中国澳门特别行政区",
            "MS": "蒙特塞拉特岛",
            "MT": "马耳他",
            "MU": "毛里求斯",
            "MV": "马尔代夫",
            "MW": "马拉维",
            "MX": "墨西哥",
            "MY": "马来西亚",
            "MZ": "莫桑比克",
            "NA": "纳米比亚",
            "NE": "尼日尔",
            "NG": "尼日利亚",
            "NI": "尼加拉瓜",
            "NL": "荷兰",
            "NO": "挪威",
            "NP": "尼泊尔",
            "NR": "瑙鲁",
            "NZ": "新西兰",
            "OM": "阿曼",
            "PA": "巴拿马",
            "PE": "秘鲁",
            "PF": "法属玻利尼西亚",
            "PG": "巴布亚新几内亚",
            "PH": "菲律宾",
            "PK": "巴基斯坦",
            "PL": "波兰",
            "PR": "波多黎各",
            "PT": "葡萄牙",
            "PY": "巴拉圭",
            "QA": "卡塔尔",
            "RO": "罗马尼亚",
            "RU": "俄罗斯",
            "SA": "沙特阿拉伯",
            "SB": "所罗门群岛",
            "SC": "塞舌尔",
            "SD": "苏丹",
            "SE": "瑞典",
            "SG": "新加坡",
            "SI": "斯洛文尼亚",
            "SK": "斯洛伐克",
            "SL": "塞拉利昂",
            "SM": "圣马力诺",
            "SN": "塞内加尔",
            "SO": "索马里",
            "SR": "苏里南",
            "ST": "圣多美和普林西比",
            "SV": "萨尔瓦多",
            "SY": "叙利亚",
            "SZ": "斯威士兰",
            "TD": "乍得",
            "TG": "多哥",
            "TH": "泰国",
            "TJ": "塔吉克斯坦",
            "TM": "土库曼斯坦",
            "TN": "突尼斯",
            "TO": "汤加",
            "TR": "土耳其",
            "TT": "特立尼达和多巴哥",
            "TW": "中国台湾省",
            "TZ": "坦桑尼亚",
            "UA": "乌克兰",
            "UG": "乌干达",
            "US": "美国",
            "UY": "乌拉圭",
            "UZ": "乌兹别克斯坦",
            "VC": "圣文森特岛",
            "VE": "委内瑞拉",
            "VN": "越南",
            "YE": "也门",
            "YU": "南斯拉夫",
            "ZA": "南非",
            "ZM": "赞比亚",
            "ZR": "扎伊尔",
            "ZW": "津巴布韦"
        }

    def agg_attack_ip(self):
        """
        aggs: This section defines the aggregations.
        tag_counts: This is the name of the primary aggregation.
        composite: This type of aggregation is used for bucketing documents into composite buckets.
        size: 1000: The number of composite buckets to return. Here, it is set to return up to 1000 buckets.

        sources: This specifies the fields to use for bucketing.
        socket_ip:
        terms: This creates buckets for unique values of the specified field.
        field: "socket_ip": The field socket_ip is used for the terms aggregation, meaning it will create a bucket for each
        unique socket_ip.

        Nested Aggregation:
        aggs: This is a sub-aggregation within tag_counts.
        filtered_results: This is a name for the bucket selector aggregation.
        bucket_selector: This is used to filter buckets based on a script.
        buckets_path: This defines paths to the buckets to be filtered.
        docCount: "_count": This sets a path to the _count meta field, which holds the count of documents in each bucket.
        script: The script to evaluate whether a bucket should be retained.
        params.docCount > 9: This script retains only those buckets where the document count (docCount) is greater than 10.
        :return:
        """
        agg_attack_ip_ = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "tag_counts": {
                    "composite": {
                        "size": 1000,
                        "sources": [
                            {
                                "socket_ip": {
                                    "terms": {
                                        "field": "socket_ip"
                                    }
                                }
                            }
                        ]
                    },
                    "aggs": {
                        "filtered_results": {
                            "bucket_selector": {
                                "buckets_path": {
                                    "docCount": "_count"
                                },
                                "script": "params.docCount > 9"
                            }
                        }
                    }
                }
            }
        }
        attack_ip = []
        try:
            logger.info('Tring to get all the IP that satisfy the aggregation rules.')
            response = self._es.search(index="logs-chaitin_waf-attack", body=agg_attack_ip_)
            # 将查询结果中的after_key提取出来，用于获取剩余的IP
            after_key = response['aggregations']['tag_counts']['after_key']['socket_ip']
            # 将聚合查询中攻击IP全部提取出来
            buckets = response['aggregations']['tag_counts']['buckets']
            attack_ip = [i['key']['socket_ip'] for i in buckets]
            while True:
                response = self.remainder_ip_search(after_key)
                try:
                    after_key = response['aggregations']['tag_counts']['after_key']['socket_ip']
                    buckets = response['aggregations']['tag_counts']['buckets']
                    attack_ip.extend([i['key']['socket_ip'] for i in buckets])
                except KeyError:
                    logger.info('No remainder IP in the response of the [remainder_ip_search] method.')
                    break
                except:
                    logger.error('An error occured while querying the [remainder_ip_search] method.', exc_info=True)
                    break
        # 这个异常捕获的是当after_key没有获取到任何地址的时候
        except KeyError:
            logger.info('Didn\'t get any IP.')
            return attack_ip
        except Exception:
            logger.error('An error occured while querying the [exist_in_block_index] method.', exc_info=True)
            raise Exception('agg_attack_ip function research error')
        logger.info('Successfully get all the attacked IP.')
        return attack_ip

    def remainder_ip_search(self, ip):
        query_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "tag_counts": {
                    "composite": {
                        "size": 1000,
                        "sources": [
                            {
                                "socket_ip": {
                                    "terms": {
                                        "field": "socket_ip"
                                    }
                                }
                            }
                        ],
                        "after": {"socket_ip": ip}
                    },
                    "aggs": {
                        "filtered_results": {
                            "bucket_selector": {
                                "buckets_path": {
                                    "docCount": "_count"
                                },
                                "script": "params.docCount > 10"
                            }
                        }
                    }
                }
            }
        }
        try:
            logger.info('Getting the remainder IP.')
            return self._es.search(index="logs-chaitin_waf-attack", body=query_json)
        except:
            logger.error('\"%s\" An error occured while querying the [remainder_ip_search] method.', ip, exc_info=True)

    def exist_in_manual_index(self, checklist):
        try:
            query_json = {
                "docs": [
                    {"_id": i} for i in checklist
                ]
            }
            response = self._es.mget(index="manual_ip_index", params={"_source": "false"}, body=query_json)
            return [i["_id"] for i in response["docs"] if i["found"]]
        except:
            logger.error('An error occured while querying the [exist_in_manual_index] method.', exc_info=True)
            return []

    def exist_in_block_index(self):
        # 获取全部的攻击IP
        result = self.agg_attack_ip()
        b = []
        if result:
            # 用攻击IP来构建查询，查询这些IP是否已经存在于block_index
            mget_body = {
                "docs": [{"_index": "blocked_ip_index", "_id": i} for i in result]
            }
            # 用攻击IP来构建查询，查询这些IP是否已经超时
            expired_ip = {
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {
                                "ids": {
                                    "values": result
                                }
                            },
                            {
                                "range": {
                                    "expire_time": {
                                        "lt": self.search_time
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            # 执行mget请求
            logger.debug('Start to check whether the attacked IP has existed in "blocked_ip_index".')
            try:
                response = self._es.mget(index="blocked_ip_index", body=mget_body)
                response2 = self._es.search(index="blocked_ip_index",
                                            params={"filter_path": "hits.hits._source.blocked_ip"}, body=expired_ip)
                if response2:
                    hits = response2['hits']['hits']
                    self._expired_ip = [i['_source']['blocked_ip'] for i in hits]
                # 处理返回的结果，返回结果格式如下：
                # {
                #     "docs": [
                #         {
                #             "_index": "blocked_ip_index",
                #             "_id": "192.168.1.1",
                #             "found": false
                #         },
                #         {
                #             "_index": "blocked_ip_index",
                #             "_id": "27.20.172.125",
                #             "_version": 5,
                #             "_seq_no": 306,
                #             "_primary_term": 1,
                #             "found": true
                #         }
                #     ]
                # }
                manual_list = self.exist_in_manual_index(result)
                # doc['found']的值为false意味着这个IP地址不存在于block_index中，需要添加到列表中进行后续处理
                b.extend(
                    [
                        doc['_id'] for doc in response['docs']
                        if not doc['found'] and doc['_id'] not in manual_list
                    ]
                )
                if b:
                    logger.info('Return the attacked IP that don\'t exist in "blocked_ip_index".')
                    return b
                else:
                    logger.info('All the attacked IP have been existed in "blocked_ip_index".')
                    return b
            # 没有找到结果会有报错，这个异常捕获的就是没有找到结果的情况
            except BadRequestError:
                logger.info('No newest attack IP are found.')
                return b
            except Exception as e:
                logger.error('An error occured while querying the [exist_in_block_index] method.', exc_info=True)
                raise Exception('An error occured while querying the [exist_in_block_index] method.')
        else:
            return b

    def start_judging(self):
        """
        1.需要将所有IP地址都汇总起来统一进行加黑,已完成
        2.加黑的时候需要通过bulk方法来批量进行添加，加黑的形参需要重新设计
        3.对于加黑前的逻辑判断需要重新调整，形参部分需要重新调整

        遗留问题：
        1.判断加黑IP的时候需要加上时间，需要分类处理  超出时间的行为
        2.给人工判断的IP是否要创建新的索引，IP是否需要写入到新索引中
        :return:
        """
        result = self.exist_in_block_index()
        if result:
            for ip in result:
                # 如果是境外IP，会被加黑，并跳过后续的逻辑判断
                if self.overseas_ip_detect(ip):
                    # block_ip_info[ip] = 1
                    continue
                response, tag = self.attack_reason_agg(ip)
                # tag == 3表示攻击类型大于等于三个，需要被加黑，并跳过后续的逻辑判断
                if tag == 3:
                    self._block_dict[ip] = 2
                    continue
                # 如果攻击了多个目标并且使用了多种类型的攻击方式，则被加黑，并跳过后续的逻辑判断
                elif self.attacked_ip_num(ip) and response:
                    self._block_dict[ip] = 3
                    continue
                # 进行攻击类型判断，如果攻击类型包含了预定义的高危攻击类型，则进行加黑，并跳过后续逻辑判断
                result, attack_type = self.attack_type_analysis(ip)
                if result:
                    continue
                # 开始逻辑判断,并将返回结果与初始的字典进行合并
                self._block_dict.update(self.logical_decision(ip, attack_type))
            if self._block_dict:
                self.add_black()
                # pprint(self._block_dict)
            if self._manual:
                self.manual_judgment()
                # pprint(self._manual)
            if self._expired_ip:
                self.refresh_expired_time()
                # pprint(self._expired_ip)
            self.send_to_ips()
            self.wechat_alert()
        else:
            # 没有获取到任何IP地址，直接结束
            return

    def overseas_ip_detect(self, ip):
        """
       检测给定的IP地址是否为中国境外的IP地址。

       参数:
       ip (str): 需要检测的IP地址。

       返回:
       bool: 如果IP地址为中国境外，则返回True；反之，返回False。
       """
        overseas_ip = {
            "size": 1,
            "_source": ["country", "socket_ip"],
            "query": {
                "match": {
                    "socket_ip": ip
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=overseas_ip)
            logger.info('\"%s\" call the [overseas_ip_detect] method for querying and '
                        'successfully obtain response data.', ip)
            country = response["hits"]["hits"][0]["_source"]['country']
            if country == 'CN':
                logger.info('The country of \"%s\" belongs to China, further inspection is required.', ip)
                return False
            else:
                logger.info('The country of \"%s\" doesn\'t belong to China. Execute [add_black] method.', ip)
                # 向字典中写入当前的IP地址，并返回True
                self._block_dict[ip] = "1" + self._country_code.get(country, "未知国家")
                return True
        except:
            logger.error('An error occured while querying the [overseas_ip_detect] method.', exc_info=True)

    def attacked_ip_num(self, ip, tag=True):
        """
           检查指定源IP是否攻击了多个目标地址。

           通过查询日志索引中与指定源IP相关且时间在特定范围内的攻击记录，统计攻击的不同目标IP数量，判断是否超过预设阈值（这里是2）。

           参数:
           - source_ip: str，要检查的源IP地址。

           返回值:
           - bool，如果该源IP攻击了超过2个目标地址，则返回True，否则返回False。
           """
        attacked_num = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attacked_num": {
                    "terms": {
                        "field": "dest_ip",
                        "size": 10
                    }
                }
            }
        }
        response = self._es.search(index="logs-chaitin_waf-attack", body=attacked_num)
        _l = response['aggregations']['attacked_num']['buckets']
        if tag:
            if len(_l) > 1:
                logger.info('\"%s\" has attacked multiple sites more than once.', ip)
                return True
            else:
                logger.info('\"%s\" has attacked only one site.', ip)
                return False
        else:
            return [i['key'] for i in _l]

    def attack_reason_agg(self, ip, tag=True):
        attack_reason = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attack_reason": {
                    "terms": {
                        "field": "reason.keyword",
                        "size": 10
                    }
                }
            }
        }
        response = self._es.search(index="logs-chaitin_waf-attack", body=attack_reason)
        _l = response['aggregations']['attack_reason']['buckets']
        if tag:
            try:
                if 1 < len(_l) <= 2:
                    logger.info('The aggregated attack reasons of \"%s\" is gt once and lte twice.', ip)
                    return True, 1
                elif len(_l) >= 3:
                    logger.info('The aggregated attack reasons of \"%s\" is gte third.', ip)
                    return True, 3
                else:
                    logger.info('The aggregated attack reason of \"%s\" is only once.', ip)
                    return False, 0
            except:
                logger.error('\"%s\" An error occured while querying the [attack_reason_agg] method.', ip,
                             exc_info=True)
                # print(f"查询Elasticsearch时出现错误: {e}")
        else:
            try:
                logger.info('Get all the aggregated attack reasons.')
                return [i['key'] for i in _l]
            except:
                logger.error('\"%s\" An error occured while querying the [attack_reason_agg] method.', ip,
                             exc_info=True)

    def attack_type_analysis(self, ip):
        """
        分析指定IP和时间范围内的攻击类型。

        参数:
        - ip: str，要查询的IP地址。
        - search_time: str，查询的起始时间，格式为YYYY-MM-DD HH:MM:SS。

        返回值:
        - bool，如果查询到的攻击类型在预定义的比较列表中，则返回True，否则返回False。
        """
        # 定义比较列表，包含多种攻击类型
        compare_list = ['scanner', 'unauthorized_access', 'code_injection', 'code_execution', 'command_injection',
                        'deserialization', 'unsafe_config']
        attack_type_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attack_type_analysis": {
                    "terms": {
                        "field": "attack_type",
                        "size": 20
                    }
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=attack_type_json)
            logger.info('\"%s\" call the [attack_type_analysis] method for querying and successfully '
                        'obtain response data.', ip)
            # 将所有的攻击类型放置到一个列表中
            attack_type = [i['key'] for i in response['aggregations']['attack_type_analysis']['buckets']]
            # 将attack_type列表中的攻击类型与compare_list列表进行比较，如果存在相同的元素，则返回True
            if True in [i in compare_list for i in attack_type]:
                logger.info('The attack type of \"%s\" was in the range of redefined list, '
                            'executed "add_black" function.', ip)
                # self.add_black(ip)
                self._block_dict[ip] = attack_type
                return True, attack_type
            logger.info('The attack type of \"%s\" didn\'t appear in the redefined list, '
                        'further inspection is required.', ip)
            return False, attack_type
        except:
            logger.error('\"%s\" An error occured while querying the [attack_type_analysis] method.', ip, exc_info=True)

    def logical_decision(self, ip, attack_type):
        # 验证参数的合法性
        if not isinstance(ip, str) or not isinstance(attack_type, list):
            raise ValueError("Invalid input types")
        finnal_dict = dict()
        for i in attack_type:
            if not finnal_dict:
                match i:
                    case 'sql_injection':
                        if self.sql_injection(ip):
                            finnal_dict[ip] = i
                    case 'info_leak':
                        if self.info_leak(ip):
                            finnal_dict[ip] = i
                    case 'xss':
                        if self.xss(ip):
                            finnal_dict[ip] = i
                    case 'xxe':
                        if self.xxe(ip):
                            finnal_dict[ip] = i
                    case 'ssrf':
                        if self.ssrf(ip):
                            finnal_dict[ip] = i
                    case 'permission_bypass':
                        if self.permission_bypass(ip):
                            finnal_dict[ip] = i
                    case 'file_inclusion':
                        if self.file_inclusion(ip):
                            finnal_dict[ip] = i
                    case 'file_upload':
                        if self.file_upload(ip):
                            finnal_dict[ip] = i
                    case 'ssti':
                        if self.ssti(ip):
                            finnal_dict[ip] = i
                    case 'directory_traversal':
                        if self.directory_traversal(ip):
                            finnal_dict[ip] = i
                    # case 'backdoor':
                    #     # 暂时不做这个攻击类型的判断，没有收集到比较明显的攻击特性做为参考
                    #     print('backdoor')
                    case _:
                        self._manual[ip] = '未命中任何预定义的攻击类型'
                        # self.manual_judgment(ip)
            else:
                break
        return finnal_dict

    def sql_injection(self, ip):
        luocs_ip = '10.168.98.99'
        # luo_ip = '10.188.166.24'
        sql_injection_json = {
            "size": 1,
            "_source": ["dest_ip"],
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "sql_injection"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=sql_injection_json)
            result = response['hits']['hits'][0]['_source']['dest_ip']
            logger.info('\"%s\" call the [sql_inject] method for querying and successfully obtain response data.', ip)
            if result == luocs_ip:
                logger.info('\"%s\" triggered [sql_inject] alarm,but the attacked website belongs to LuoCS，'
                            'Execute "manual_judgment" function.', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发[sql_inject]告警，但是被攻击的网站属于罗长书'
                return False
            else:
                logger.info('\"%s\" triggered [sql_inject] alarm,executed "add_black" function.', ip)
                # self.add_black(ip)
                return True
            # pprint(result)
        except Exception as e:
            logger.error('\"%s\" An error occured while querying the [sql_inject] method.', ip, exc_info=True)
            # print(f"查询Elasticsearch时出现错误: {e}")

    def info_leak(self, ip):
        """
       在这里特别注意（*.sql），我花了很长时间来研究，我一开始想用（.sql）来做搜索，因为根据官网的解释，
       使用（*.sql）会有性能问题，但是使用（.sql）来做搜索，会检索到1和2两个URL，原因是在搜索前会对
       .sql进行分词，分词后的term就变成了sql，而在对字段做搜索时，也会对URL做分词，因此1和2都被匹配了，
       而我只想要匹配包含以.sql结尾url，所以只能用（*.sql）,所以下面的query语句中，其实所有的词前面都没有
       必要加上.这个符号，因为会在分词的时候给删除掉，除非手动修改分词器，将.和后面的词作为一个整体，但是
       重新配置分词器太麻烦，而且还要修改索引模板的mapping配置，我实在不想弄了！！！
       1./sql/myadmin/index.php?lang=en
       2./phpMyAdmin/phpcms/modules/comment/install/module.sql
       """
        info_leak_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "info_leak"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        },
                        {
                            "query_string": {
                                "default_field": "urlpath",
                                "query": "(.git) OR (.env) OR (*.sql) OR (.DS_Store) OR "
                                         "/(db|root|wwwroot|database).(rar|zip|7z)/ "
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=info_leak_json)
            logger.info('\"%s\" call the [info_leak] method for querying and successfully obtain response data.', ip)
            if response['hits']['total']['value'] == 0:
                logger.info('\"%s\" triggered [info_leak] alarm.The predefined sensitive keywords were not found'
                            ' in urlpath.Execute "manual_judgment" function.', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发[info_leak]告警，但是在urlpath中没有发现预定义的敏感词'
                return False
            else:
                logger.info('\"%s\" triggered [info_leak] alarm.The predefined sensitive keywords were found'
                            ' in urlpath.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
            # pprint(result)
        except:
            logger.error('\"%s\" An error occured while querying the [info_leak] method.', ip, exc_info=True)
            # print(f"查询Elasticsearch时出现错误: {e}")

    def xss(self, ip):
        xss_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "xss"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "location_agg": {
                    "terms": {"field": "location"}
                },
                "risk_agg": {
                    "terms": {"field": "req_risk_level"}
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=xss_json)
            # # 获取XSS的攻击位置，如果不在body中，则直接添加黑名单
            # result = response['aggregations']['location_agg']['buckets']
            # logger.info('\"%s\" call the [XSS] method for querying and successfully obtain response data.', ip)
            # # 将XSS的攻击位置，转换为列表
            # temp = [i['key'] for i in result]
            # if len(temp) > 1:
            #     logger.info('\"%s\" triggered [XSS] alarm.The payload that triggered the [XSS] alarm was found in '
            #                 'http head.Execute \"add_black\" function.', ip)
            #     add_black(ip, search_time)
            # elif 'body' in temp:
            #     # 如果是在body中的载荷触发了XSS的告警，则需要判断其风险等级
            #     # 如果风险等级只有低危和中危，则需要人工判断
            #     # 如果存在高危，则添加黑名单
            #     result = response['aggregations']['risk_agg']['buckets']
            #     temp = [i['key'] for i in result]
            #     if 'high' in temp:
            #         logger.info('\"%s\" triggered [xss] alarm.The payload that triggered the [XSS] alarm was found in'
            #                     'http body ,and the risk level was assessed as high.'
            #                     'Execute "shanghai_net_detect" function.', ip)
            #         shanghai_net_detect(ip, search_time)
            #     else:
            #         logger.info('\"%s\" triggered [xss] alarm.The payload that triggered the [XSS] alarm was found in'
            #                     'http body,and the risk level was assessed as moderate to low.'
            #                     'Execute "manual_judgment" function.', ip)
            #         manual_judgment(ip)
            # else:
            #     # 如果一个报文其触发了XSS告警的载荷，是位于web 头部的字段，则直接添加黑名单
            #     logger.info('\"%s\" triggered [xss] alarm.The payload that triggered the [XSS] alarm was found in '
            #                 'http head.Execute \"add_black\" function.', ip)
            #     add_black(ip, search_time)
            logger.info('\"%s\" call the [xss] method for querying and successfully obtain response data.', ip)
            location_result = response['aggregations'].get('location_agg', {}).get('buckets', [])
            risk_result = response['aggregations'].get('risk_agg', {}).get('buckets', [])
            if any('body' == i['key'] for i in location_result):
                if 'high' in [i['key'] for i in risk_result]:
                    # 当逻辑判断走到这里，说明获触发了XSS告警的威胁级别为高，并且触发了XSS告警的攻击位置在body中
                    logger.info('\"%s\" triggered [xss] alarm. The payload was found in http body with high risk level.'
                                'Execute "shanghai_net_detect" function.', ip)
                    if self.shanghai_net_detect(ip, 'xss'):
                        return True
                    else:
                        return False
                else:
                    # 当逻辑判断走到这里，说明获触发了XSS告警的威胁级别为中低，需要人工判断
                    logger.info(
                        '\"%s\" triggered [xss] alarm. The payload was found in http body with moderate to '
                        'low risk level.'
                        'Execute "manual_judgment" function.', ip)
                    # self.manual_judgment(ip)
                    self._manual[ip] = '触发了[XSS]告警，触发的载荷位于http body中，且风险级别为中低'
                    return False
            else:
                # 当逻辑判断走到这里，说明获触发了XSS告警的攻击位置位于http头部的字段，直接添加黑名单
                logger.info('\"%s\" triggered [xss] alarm. The payload was found in http head.'
                            'Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [XSS] method.', ip, exc_info=True)
            # print(f"查询Elasticsearch时出现错误: {e}")

    def xxe(self, ip):
        xxe_json = {
            "size": 0,
            "_source": "false",
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "xxe"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        },
                        {
                            "query_string": {
                                "default_field": "body",
                                "query": "(file) OR /http?/"
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=xxe_json)
            result = response['hits']['total']['value']
            logger.info('\"%s\" call the [XXE] method for querying and successfully obtain response data.', ip)
            if result == 0:
                logger.info('\"%s\" triggered [XXE] alarm,its http body didn\'t contain the keywords about '
                            'file or http.Require "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[XXE]告警，触发的载荷没有包含file或者http关键字'
                return False
            else:
                logger.info('\"%s\" triggered [XXE] alarm,its http body contained the keywords about '
                            'file or http.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [XXR] method.', ip, exc_info=True)
            # print(f"查询Elasticsearch时出现错误: {e}")

    def ssrf(self, ip):
        ssrf_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "ssrf"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "ssrf_agg": {
                    "terms": {"field": "reason.keyword"}
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=ssrf_json)
            result = response['aggregations']['ssrf_agg']['buckets']
            logger.info('\"%s\" call the [SSRF] method for querying and successfully obtain response data.', ip)
            temp = [i['key'] for i in result]
            if len(temp) == 1 and "检测到 SSRF 攻击" in temp:
                logger.info('\"%s\" only triggered the default [SSRF] alarm and requires "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[SSRF]告警，但是在攻击原因的聚合查询中只检测到了默认的SSRF攻击'
                return False
            else:
                logger.info('\"%s\" triggered the [SSRF] alarm by multiple reasons.Execute "add_black" function.', ip)
                if self.shanghai_net_detect(ip, 'ssrf'):
                    return True
                else:
                    return False
        except:
            logger.error('\"%s\" An error occured while querying the [SSRF] method.', ip, exc_info=True)
            # print(f"查询Elasticsearch时出现错误: {e}")

    def permission_bypass(self, ip):
        permission_bypass_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "permission_bypass"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        },
                        {
                            "query_string": {
                                "default_field": "reason",
                                "query": "(cve)"
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=permission_bypass_json)
            result = response['hits']['total']['value']
            logger.info(
                '\"%s\" call the [permission Bypass] method for querying and successfully obtain response data.',
                ip)
            if result == 0:
                logger.info('\"%s\" triggered [permission Bypass] alarm, its reason field didn\'t contain the '
                            'keywords releated to CVE .Require "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[permission Bypass]告警，触发的载荷没有包含CVE攻击'
                return False
            else:
                logger.info('\"%s\" triggered [permission Bypass] alarm, its reason field  contained the '
                            'keywords releated to CVE.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [permission_bypass] method.', ip, exc_info=True)

    def file_inclusion(self, ip):
        file_inclusion_json = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "file_inclusion"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        },
                        # {
                        #     "query_string": {
                        #         "default_field": "urlpath",
                        #         "query": "(etc/passwd) OR (http) OR (win.ini)"
                        #     }
                        # }
                    ]
                }
            },
            "aggs": {
                "file_agg": {
                    "terms": {
                        "field": "urlpath.keyword",
                        "size": 20
                    }
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=file_inclusion_json)
            # result = response['hits']['total']['value']
            result = response['aggregations']['file_agg']['buckets']
            logger.info('\"%s\" call the [file_inclusion] method for querying and successfully obtain response data.',
                        ip)
            for i in result:
                if re.search(r'(\.\./){2}|win\.ini|web\.xml|etc/passwd|http(s)?:|(\\\\\.\.){2}|file:', i["key"]):
                    logger.info('\"%s\" triggered [file_inclusion] alarm, its urlpath field  contained the '
                                'predefined sensitive keywords.Execute "add_black" function.', ip)
                    # self.add_black(ip)
                    return True
            logger.info('\"%s\" triggered [file_inclusion] alarm, its urlpath field didn\'t contain the '
                        'predefined sensitive keywords.Require "manual judgment".', ip)
            # self.manual_judgment(ip)
            self._manual[ip] = '触发了[file_inclusion]告警，触发的载荷没有包含预定义的敏感词'
            return False
        except:
            logger.error('\"%s\" An error occured while querying the [file_inclusion] method.', ip, exc_info=True)

    def file_upload(self, ip):
        file_upload_json = {
            "size": 0,
            "_source": "false",
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "file_upload"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "terms": {
                                "module.keyword": [
                                    "m_php_code_injection",
                                    "m_java"
                                ]
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=file_upload_json)
            result = response['hits']['total']['value']
            logger.info('\"%s\" call the [file_upload] method for querying and successfully obtain response data.',
                        ip)
            if result == 0:
                logger.info('\"%s\" triggered [file_upload] alarm, but no injection behavior was found in the  '
                            'module field.Require "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[file_upload]告警，但是在module字段中没有发现注入行为'
                return False
            else:
                logger.info('\"%s\" triggered [file_upload] alarm,and an injection behavior was found in the '
                            'module field.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [file_upload] method.', ip, exc_info=True)

    def ssti(self, ip):
        ssti_json = {
            "size": 0,
            "_source": "false",
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "ssti"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "terms": {
                                "location": [
                                    "urlpath",
                                    "headers"
                                ]
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=ssti_json)
            result = response['hits']['total']['value']
            logger.info('\"%s\" call the [ssti] method for querying and successfully obtain response data.',
                        ip)
            if result == 0:
                logger.info('\"%s\" triggered [ssti] alarm, but the payload that tiggered SSTI alarm wasn\'t found '
                            'in predesigned location.Require "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[ssti]告警，但是触发SSTI告警的载荷不在urlpath和headers中'
                return False
            else:
                logger.info('\"%s\" triggered [ssti] alarm, and the payload that tiggered SSTI alarm was found '
                            'in predesigned location.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [ssti] method.', ip, exc_info=True)

    def directory_traversal(self, ip):
        directory_traversal_json = {
            "size": 0,
            "_source": "false",
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "attack_type": "directory_traversal"
                            }
                        },
                        {
                            "term": {
                                "socket_ip": ip
                            }
                        },
                        {
                            "range": {
                                "timestamp_human": {
                                    "gte": self.search_time
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "dt_aggs": {
                    "terms": {
                        "field": "urlpath.keyword",
                        "size": 10
                    }
                }
            }
        }
        try:
            response = self._es.search(index="logs-chaitin_waf-attack", body=directory_traversal_json)
            result = response['aggregations']['dt_aggs']['buckets']
            logger.info(
                '\"%s\" call the [directory_traversal] method for querying and successfully obtain response data.',
                ip)
            temp = [1 for i in result if re.search(r'(\.\./){2}', i['key'])]
            if len(temp) == 0:
                logger.info('\"%s\" triggered [directory_traversal] alarm, but no path traversal symbols were found '
                            'in the urlpath.Require "manual judgment".', ip)
                # self.manual_judgment(ip)
                self._manual[ip] = '触发了[directory_traversal]告警，但是urlpath中没有发现路径遍历符号'
                return False
            else:
                logger.info('\"%s\" triggered [directory_traversal] alarm, and path traversal symbols were found '
                            'in the urlpath.Execute "add_black" function.', ip)
                # self.add_black(ip)
                return True
        except:
            logger.error('\"%s\" An error occured while querying the [directory_traversal] method.', ip, exc_info=True)

    def shanghai_net_detect(self, ip, attack_type):
        # 123.132.43.133 山东
        # 114.86.94.216 上海
        shanghai_net = IP("180.0.0.0/8")
        # shanghai_net = IP("123.0.0.0/8")
        # # shanghai_net = IP("114.0.0.0/8")
        if ip in shanghai_net:
            province_search = {
                "size": 1,
                "_source": ["province"],
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "socket_ip": ip
                                }
                            },
                            {
                                "range": {
                                    "timestamp_human": {
                                        "gte": self.search_time
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            response = self._es.search(index="logs-chaitin_waf-attack", body=province_search)
            if response["hits"]["hits"][0]["_source"]['province'] == '上海':
                if attack_type == 'xss':
                    self._manual[ip] = '触发了[xss]告警，因该IP为180网段且归属地为上海'
                elif attack_type == 'ssrf':
                    self._manual[ip] = '触发了[ssrf]告警，因该IP为180网段且归属地为上海'
                return False
            else:
                self._block_dict[ip] = attack_type
                return True
        else:
            self._block_dict[ip] = attack_type
            return True

    def manual_judgment(self):
        # self._manual = {
        #     "1.1.1.1": '触发[sql_inject]告警，但是被攻击的网站属于罗长书',
        #     "1.1.1.2": '触发[info_leak]告警，但是在urlpath中没有发现预定义的敏感词',
        #     "1.1.1.3": '触发了[permission Bypass]告警，触发的载荷没有包含CVE攻击',
        # }
        env = Environment(loader=FileSystemLoader('third_party_resources'))
        wx_template = env.get_template("manual_notice.j2")
        wx = WeChat()
        for ip, event in self._manual.items():
            sites = ', '.join(self.attacked_ip_num(ip, tag=False))
            # sites = "192.168.1.1, 192.168.1.2"
            wx_result = wx_template.render(IP=ip, c_time=self.current_time, event=event, sites=sites)
            logger.info('\"%s\" send WeChat alert.', ip)
            try:
                wx.send_markdown(wx_result)
            except:
                logger.error('\"%s\" send WeChat alert failed.', ip)
        add_manualip = [
            {
                "_op_type": "create",
                "_index": "manual_ip_index",
                "_id": i,
                "add_time": self.current_time,
                "blocked_ip": i,
            } for i in self._manual.keys()
        ]
        try:
            successes, errors = bulk(self._es, add_manualip)
            logger.info(f"成功写入 {successes} 条[manual_judgment]数据")
            if errors:
                for error in errors:
                    logger.error(f"发生错误: {error}")
        except Exception as e:
            logger.error(f"批量写入时遇到错误: {e}")

    def search_index_id(self, index, id_, tag):
        try:
            response = self._es.get(index=index, id=id_)
            if tag == 'b':
                # print(response.get('found', False))
                return response.get('found', False)
            elif tag == 'm':
                return
        except NotFoundError:
            print('not found')
            return False
        except Exception as e:
            print(e)

    def add_black(self):
        formate_time = datetime.strptime(self.current_time, '%Y-%m-%d %H:%M:%S')
        expire_time = (formate_time + timedelta(days=30)).strftime('%Y-%m-%d')
        add_blackip = [
            {
                "_op_type": "create",
                "_index": "blocked_ip_index",
                "_id": i,
                "add_time": self.current_time,
                "expire_time": expire_time,
                "blocked_ip": i,
            } for i in self._block_dict.keys()
        ]
        # 使用bulk方法执行批量写入
        try:
            successes, errors = bulk(self._es, add_blackip)
            logger.info(f"成功写入 {successes} 条[add_black]数据")
            if errors:
                for error in errors:
                    logger.error(f"发生错误: {error}")
        except Exception as e:
            logger.error(f"批量写入时遇到错误: {e}")

    def refresh_expired_time(self):
        formate_time = datetime.strptime(self.current_time, '%Y-%m-%d %H:%M:%S')
        expire_time = (formate_time + timedelta(days=90)).strftime('%Y-%m-%d')
        query_json = [
            {
                # 注意这里的bulk批量写用的是update方法，其语法格式和前面的index方法不一样
                "_op_type": "update",
                "_index": "blocked_ip_index",
                "_id": i,
                "doc": {
                    "expire_time": expire_time,
                    "refresh_time": self.current_time
                }
            } for i in self._expired_ip
        ]
        # 使用bulk方法执行批量写入
        try:
            successes, errors = bulk(self._es, query_json)
            logger.info(f"成功写入 {successes} 条[refresh_expired_time]数据")
            if errors:
                for error in errors:
                    logger.error(f"发生错误: {error}")
        except Exception as e:
            logger.error(f"批量写入时遇到错误: {e}")

    def send_to_ips(self):
        blackip_list = []
        if self._block_dict:
            blackip_list.extend(self._block_dict.keys())
        if self._expired_ip:
            blackip_list.extend(self._expired_ip)
        if blackip_list:
            try:
                _myobj = NsfocusAPIv2(self._login_account, self._loging_password)
                # 循环调用API，将blackip_list分发到每个IP地址
                for ips_ip in self._target_ips:
                    _myobj.manual_post_blacklist_many(ips_ip, blackip_list)
            except Exception as e:
                print(f"Error occurred while sending blacklist: {e}")

    def wechat_alert(self):
        # 模板的位置；这里用到jinja2的模板，这个模板主要是为发送的企微告警提供模板
        env = Environment(loader=FileSystemLoader('third_party_resources'))
        wx = WeChat()
        wx_result = ''
        for k, v in self._block_dict.items():
            sites = ', '.join(self.attacked_ip_num(k, tag=False))
            if isinstance(v, int):
                reason = self._event_mapping[v]
                event = self.attack_reason_agg(k, tag=False)
                wx_template = env.get_template("common_notice.j2")
                wx_result = wx_template.render(IP=k, c_time=self.current_time, reason=reason,
                                               sites=sites, event=event)
            elif isinstance(v, str):
                # 字符串以1为开头说明是境外IP
                if v.startswith('1'):
                    event = ', '.join(self.attack_reason_agg(k, tag=False))
                    wx_template = env.get_template("abroad_notice.j2")
                    wx_result = wx_template.render(IP=k, c_time=self.current_time, country=v[1:],
                                                   sites=sites, event=event)
                else:
                    # 明细的告警
                    event = self._event_mapping[v]
                    wx_template = env.get_template("exact_notice.j2")
                    wx_result = wx_template.render(exact=v, IP=k, c_time=self.current_time,
                                                   sites=sites, event=event)
            elif isinstance(v, list):
                event = ', '.join(v)
                reason = "攻击手段中含有扫描、非授权访问、命令注入、命令执行或反序列化攻击"
                wx_template = env.get_template("common_notice.j2")
                wx_result = wx_template.render(IP=k, c_time=self.current_time, reason=reason,
                                               sites=sites, event=event)
            # print(wx_result)
            # 使用微信的send_markdown方法将jinja2生成的markdown语句发送出去
            logger.info('\"%s\" send WeChat alert.', k)
            try:
                wx.send_markdown(wx_result)
            except:
                logger.error('\"%s\" send WeChat alert failed.', k)


if __name__ == '__main__':
    # print(overseas_ip_detect("123.244.131.111"))
    # print(attacked_ip_num("222.65.128.137"))
    # print(attack_reason_agg("222.65.128.137"))
    # mysql_user = os.getenv('MySQL_PWD')
    # print(mysql_user)  # None
    # SSH_TTY = os.getenv('SSH_TTY')
    # print(SSH_TTY)  # /dev/pts/1
    # for key, value in os.environ.items():
    #     print(f"{key}: {value}")
    # sql_injection('222.67.134.132', '2024-04-29 10:00:00')
    # info_leak('47.96.91.95', '2024-04-28 00:00:00')
    # xss('222.67.134.132', '2024-04-28 00:00:00')
    # xxe('217.148.142.19', '2024-04-15 00:00:00')
    # ssrf('222.65.128.137', '2024-04-13 00:00:00')
    # ssrf('163.125.197.202', '2024-04-13 00:00:00')
    # permission_bypass('222.65.128.137', '2024-04-13 00:00:00')
    # file_inclusion("150.129.216.206", "2024-04-20 09:40:00")
    # add_black("192.168.1.3", '2024-04-20 09:40:00')
    # result = search_index_id("blocked_ip_index", '192.168.12.1','b')
    # print(result)
    # json1 = {'_index': 'blocked_ip_index', '_id': '192.168.1.1', '_version': 1, '_seq_no': 0, '_primary_term': 1,
    #          'found': True,
    #          '_source':
    #              {'blocked_ip': '192.168.1.1', 'add_time': '2024-04-15 15:00:00'}
    #          }
    # print(result)
    # myobj = ELKChaiTin("2024-05-30 00:00:00")
    # aa = myobj.agg_attack_ip()
    # aa = myobj.exist_in_block_index()
    # aa = myobj.attack_type_analysis('27.20.51.129')
    # myobj.refresh_expired()
    # print(aa)
    # print(aa)
    # remainder_ip_search('154.86.128.221', "2024-05-10 00:00:00")
    # remainder_ip_search('115.56.115.47', "2024-05-13 00:00:00")
    # remainder_ip_search('170.64.177.174', "2024-05-13 00:00:00")
    # remainder_ip_search('223.244.123.144', "2024-05-13 00:00:00")
    pass
