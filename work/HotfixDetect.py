
# coding=utf-8

import threading
import json
import pythoncom
import wmi

from util.EncryptUtil import EncryptUtil


class HotfixDetect(threading.Thread):
    """
    用于探测补丁信息的类
    """
    def __init__(self, mq, data):
        super().__init__()
        # mq: RabbitMQ 实例
        self.__mq = mq
        # data: 需要检测的补丁数据
        self.__data = data

    def run(self):
        self.__detect_hotfix()

    def __detect_hotfix(self):
        """
        补丁发现
        :return:
        """
        print("开始补丁安全发现......!")
        # 初始化
        pythoncom.CoInitialize()
        # 创建WMI客户端
        c = wmi.WMI()
        # 获取补丁信息
        hotfixes = c.query("SELECT HotFixID FROM Win32_QuickFixEngineering")
        # 组装补丁ID
        hotfix_list = []
        for hotfix in hotfixes:
            data = {
                'macAddress': self.__data['macAddress'],
                'hotfixId': hotfix.HotFixID
            }
            hotfix_list.append(data)
        # 去初始化
        pythoncom.CoUninitialize()
        # 转换成JSON数据
        data = json.dumps(hotfix_list)
        print(data)
        encrypted_data = EncryptUtil.encrypt_json(data, "thisIsASecretKey")
        print("加密后的数据:", encrypted_data)
        self.__mq.produce_hotfix_data(encrypted_data)
        # 发送到队列
        #self.__mq.produce_hotfix_data(data)
        print("补丁安全发现结束")