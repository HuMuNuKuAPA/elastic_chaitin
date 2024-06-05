#!/usr/local/bin/python3
# -*- coding=utf-8 -*-
# 作者：呼姆呼姆
# 邮箱：wuzhiping26@gmail.com
import unittest
from unittest.mock import MagicMock, patch
from analyze_ChaiTin import add_black  # 确保这个引用路径和模块名可以正确找到目标函数


# Mock Elasticsearch 对象
class MockElasticsearch:
    def index(self, index, id, body):
        # 根据需要定制 mock 行为
        if id in ["already_exists"]:
            raise ValueError("already in blocked_ip_index")
        return {"result": "created"}


class TestAddBlack(unittest.TestCase):

    @patch('analyze_ChaiTin.search_index_id', return_value=False)  # Mock search_index_id 函数
    @patch('analyze_ChaiTin.es', new_callable=MockElasticsearch)  # Mock Elasticsearch 实例
    def test_add_black_new_ip(self, mock_es, mock_search_index_id):
        """
        测试向 blocked_ip_index 中添加一个新的 IP 地址。
        """
        ip = "192.168.10.1"
        search_time = "2023-04-01T00:00:00"

        # 调用待测函数
        add_black(ip, search_time)

        # 验证是否调用了 Elasticsearch 的 index 方法
        mock_es.index.assert_called_once_with(index="blocked_ip_index", id=ip, body={
            "blocked_ip": ip,
            "add_time": search_time
        })

    @patch('analyze_ChaiTin.search_index_id', return_value=True)  # Mock search_index_id 函数，假设 IP 已存在
    def test_add_black_existing_ip(self, mock_search_index_id):
        """
        测试当 IP 地址已经存在于 blocked_ip_index 时，函数的行为。
        """
        ip = "192.168.1.1"
        search_time = "2023-04-01T00:00:00"

        # 调用待测函数
        with self.assertLogs(level='INFO') as log:
            add_black(ip, search_time)

        # 验证日志中记录的信息
        self.assertIn('already in blocked_ip_index', log.output[0])


# 运行测试
if __name__ == '__main__':
    unittest.main()