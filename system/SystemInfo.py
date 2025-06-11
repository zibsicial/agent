#coding=utf-8
import json
import math
import platform
import socket
import uuid

import psutil


class SystemInfo(object):
    #
    # 1.主机名
    # 2.主机IP
    # 3.主机MAC
    # 4.主机操作系统
    # 5.主机操作系统具体型号
    # 6.主机具体系统版本号
    # 7.主机位数
    # 8.主机CPU
    # 9.主机内存
    #
    def __init__(self):
        #主机名
        self.__host_name = ""
        #主机IP地址
        self.__ip_address = ""
        #主机MAC地址
        self.__mac_address = ""
        #主机的操作系统
        self.__os_type = ""
        #主机操作系统具体的型号
        self.__os_name = ""
        #主机操作系统版本号
        self.__os_version = ""
        #主机的操作系统位数
        self.__os_bit = ""
        #主机的CPU
        self.__cpu_name = ""
        #主机的内存
        self.__ram = ""
        #状态
        self.status = 1


    def get_mac_address(self):
        return self.__mac_address


    def set_status(self,status):
        if status in (0,1):
            self.status = status
        else:
            raise ValueError("status参数错误")


    def __get_hostname(self):
        """
        获取主机名
        :return:
        """
        self.__host_name = socket.gethostname()


    def __get_ip(self):
        """
        获取IP地址
        :return:
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("114.114.114.114", 80))
        ip_address = s.getsockname()[0]
        s.close()
        self.__ip_address = ip_address


    def __get_mac(self):
        """
        获取MAC地址: 这个是逻辑MAC，但也是唯一的，只是做一个标识
        :return:
        """
        mac = ':'.join(("%012X" % uuid.getnode())[i:i + 2] for i in range(0, 12, 2))
        self.__mac_address = mac


    def __get_os_type(self):
        """
        获取操作系统相关信息
        :return:
        """
        self.__os_type = platform.system()
        # 这个地方获取的可能和操作系统里面显示的不一样，显示的是出厂的操作系统
        self.__os_name = platform.platform()
        # 这个可以获取实际的操作系统版本，但是不跨平台
        # self.__os_name = self.get_win_os_name()
        self.__os_version = platform.version()
        self.__os_bit = platform.architecture()[0]


    def __get_cpu_ram_info(self):
        """
        获取cpu,ram相关信息
        :return:
        """
        self.__cpu_name = platform.processor()
        self.__ram = math.ceil(psutil.virtual_memory().total / 1024 / 1024 / 1024)


    def get_info(self):
        """
        获取基本信息的方法
        :return:
        """
        self.__get_hostname()
        self.__get_ip()
        self.__get_mac()
        self.__get_os_type()
        self.__get_cpu_ram_info()
        #要返回JSON数据，把所有信息封装成一个字典
        info = {
            "hostName": self.__host_name,
            "ipAddress": self.__ip_address,
            "macAddress": self.__mac_address,
            "osType": self.__os_type,
            "osName": self.__os_name,
            "osVersion": self.__os_version,
            "osBit": self.__os_bit,
            "cpuName": self.__cpu_name,
            "ram": self.__ram,
        }
        #将info转换为JSON

        return json.dumps(info)



