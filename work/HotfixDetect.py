# coding=utf-8

import threading
import json
import platform
import subprocess
from util.EncryptUtil import EncryptUtil
# Windows 专用库
if platform.system() == "Windows":
    import pythoncom
    import wmi


class HotfixDetect(threading.Thread):
    """
    用于探测补丁信息的类，支持 Windows 和 Linux
    """
    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data
        self.__is_windows = platform.system() == "Windows"

    def run(self):
        self.__detect_hotfix()

    def __detect_hotfix(self):
        """
        补丁发现
        """
        print("开始补丁安全发现......!")
        hotfix_list = []

        if self.__is_windows:
            hotfix_list = self.__detect_windows_hotfix()
        else:
            hotfix_list = self.__detect_linux_hotfix()

        # 转换成 JSON 数据
        data = json.dumps(hotfix_list)
        print(data)
        encrypted_data = EncryptUtil.encrypt_json(data, "thisIsASecretKey")
        print("加密后的数据:", encrypted_data)
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_hotfix_data(encrypted_data)
        print("补丁安全发现结束")

    def __detect_windows_hotfix(self):
        """
        Windows 补丁发现
        """
        hotfix_list = []
        try:
            # 初始化 WMI
            pythoncom.CoInitialize()
            c = wmi.WMI()
            # 获取补丁信息
            hotfixes = c.query("SELECT HotFixID FROM Win32_QuickFixEngineering")
            for hotfix in hotfixes:
                data = {
                    'macAddress': self.__data['macAddress'],
                    'hotfixId': hotfix.HotFixID
                }
                hotfix_list.append(data)
        except Exception as e:
            print(f"[!] Windows 补丁检测失败: {e}")
        finally:
            # 去初始化
            pythoncom.CoUninitialize()
        return hotfix_list

    def __detect_linux_hotfix(self):
        """
        Linux 补丁发现
        """
        hotfix_list = []
        try:
            # 检查 dpkg.log 或 yum history
            if platform.system() == "Linux":
                if subprocess.call(["which", "dpkg"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                    # 使用 dpkg.log 检测补丁
                    with open("/var/log/dpkg.log", "r") as f:
                        for line in f:
                            if "install" in line:
                                parts = line.split()
                                hotfix_list.append({
                                    'macAddress': self.__data['macAddress'],
                                    'hotfixId': parts[-1]
                                })
                elif subprocess.call(["which", "yum"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                    # 使用 yum history 检测补丁
                    result = subprocess.run(["yum", "history", "list"], stdout=subprocess.PIPE, text=True)
                    for line in result.stdout.splitlines():
                        if line.strip() and not line.startswith("ID"):
                            parts = line.split()
                            hotfix_list.append({
                                'macAddress': self.__data['macAddress'],
                                'hotfixId': parts[-1]
                            })
        except FileNotFoundError:
            print("[!] 无法读取补丁信息文件")
        except Exception as e:
            print(f"[!] Linux 补丁检测失败: {e}")
        return hotfix_list