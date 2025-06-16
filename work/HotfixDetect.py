import threading
import json
import pythoncom
import wmi


class HotfixDetect(threading.Thread):
    def __init__(self,mq,data):
        super().__init__()
        self.__mq = mq
        # 平台传递的指令
        self.__data = data

    def  run(self):
        """
        线程运行函数
        """
        self.__hotfix_detect()

    def __hotfix_detect(self):
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
                'mac': self.__data['mac'],
                'hotfixId': hotfix.HotFixID
            }
        hotfix_list.append(data)
        # 去初始化
        pythoncom.CoUninitialize()
        # 转换成JSON数据
        data = json.dumps(hotfix_list)
        # 发送到队列
        self.__mq.produce_hotfix_info(data)
        print("补丁安全发现结束")