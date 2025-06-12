import json
import threading
import winreg

import pythoncom
import wmi
from nmap import nmap
from util.EncryptUtil import EncryptUtil

class AssetsDetect(threading.Thread):
    """
    资产探测的线程类
    """
    def __init__(self,mq,data):
        super().__init__()
        self.__mq = mq
        #平台传递的指令
        self.__data = data

    def  run(self):
        """
        线程运行函数
        """
        self.__detect()

    #检测资产
    def __detect(self):
        """
        探测的方法
        :return:
        """
        #需要探测四个类型的资产
        #account,service,process,app
        account = self.__data["account"]
        service = self.__data["service"]
        process = self.__data["process"]
        app = self.__data["app"]
        if account == 1:
            self.__detect_account()

        if service == 1:
            self.__detect_service()

        if process == 1:
            self.__detect_process()

        if app == 1:
            self.__detect_app()



    #检测账户
    def __detect_account(self):
        """
        探测账号资产
        :return:
        """
        # 创建wmi客户端对象
        # 初始化
        pythoncom.CoInitialize()
        c = wmi.WMI()
        account_list = []
        # 获取所有用户
        for user in c.Win32_UserAccount():
            user_dict = {
                "macAddress": self.__data['macAddress'],
                "name": user.Name,
                "fullName": user.FullName,
                "sid": user.SID,
                "sidType": user.SIDType,
                "status": user.Status,
                "disabled": user.Disabled,
                "lockout": user.Lockout,
                "passwordChangeable": user.PasswordChangeable,
                "passwordExpires": user.PasswordExpires,
                "passwordRequired": user.PasswordRequired,
            }
            account_list.append(user_dict)
        # 去初始化
        pythoncom.CoUninitialize()
        # 转换成JSON字符串
        account_data = json.dumps(account_list)
        #加密
        encrypted_account_data = EncryptUtil.encrypt_json(account_data, "thisIsASecretKey")
        print(account_data)
        #将探测到的信息发送到MQ
        self.__mq.produce_account_info(encrypted_account_data)

    #检测服务
    def __detect_service(self):
        """
        探测服务资产
        :return:
        """
        print('开始探测服务数据......!')
        # 创建一个扫描仪对象
        nm = nmap.PortScanner()
        # 扫描目标主机
        nm.scan(hosts='127.0.0.1', arguments='-sTV')  # 指定扫描端口范围
        # 获取扫描结果
        state = nm.all_hosts()
        # 装最终结果的
        res_list = []
        if state:
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                    # 接收nmap扫描结果
                        nmap_res = {
                            'macAddress': self.__data['macAddress'],
                            'protocol': proto,
                            'port': port,
                            'state': nm[host][proto][port]['state'],
                            'name': nm[host][proto][port]['name'],
                            'product': nm[host][proto][port]['product'],
                            'version': nm[host][proto][port]['version'],
                            'extraInfo': nm[host][proto][port].get('extraInfo', 'N/A')
                        }
                        res_list.append(nmap_res)
        # 转换成JSON字符串
        service_data = json.dumps(res_list)
        encrypted_service_data = EncryptUtil.encrypt_json(service_data, "thisIsASecretKey")
        print(service_data)
        # 发送到队列
        self.__mq.produce_service_info(encrypted_service_data)
        print("服务数据探测结束！")

    def __detect_process(self):
        # 获取进程信息
        # 初始化
        print('开始探测进程数据......!')
        pythoncom.CoInitialize()
        c = wmi.WMI()
        process_list = []
        for process in c.Win32_Process():
            process_info = {
                'macAddress': self.__data['macAddress'],
                'pid': process.ProcessId,
                'ppid': process.ParentProcessId,
                'name': process.Name,
                'cmd': process.CommandLine,
                'priority': process.Priority,
                'description': process.Description,
            }
            process_list.append(process_info)
        # 去初始化
        pythoncom.CoUninitialize()
        # 转换成JSON
        process_data = json.dumps(process_list)
        encrypted_process_data = EncryptUtil.encrypt_json(process_data, "thisIsASecretKey")
        print(process_data)
        # 发送到队列
        self.__mq.produce_process_info(encrypted_process_data)
        print("进程数据探测结束！")


    def __detect_app(self):
        # 从注册表获取软件信息
        print('开始探测app数据......!')
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
        software_list = []
        # 获取软件数量
        number = winreg.QueryInfoKey(registry_key)[0]
        for i in range(number):
            try:
                sub_key_name = winreg.EnumKey(registry_key, i)
                sub_key = winreg.OpenKey(registry_key, sub_key_name)
                software = {}
                try:
                    software['macAddress'] = self.__data['macAddress']
                    software['displayName'] = winreg.QueryValueEx(sub_key,'DisplayName')[0]
                    software['installLocation'] = winreg.QueryValueEx(sub_key,'InstallLocation')[0]
                    software['uninstallString'] = winreg.QueryValueEx(sub_key,'UninstallString')[0]
                    software_list.append(software)
                except WindowsError:
                    continue
            except WindowsError:
                break
        # 转换成JSON字符串
        app_data = json.dumps(software_list)
        encrypted_app_data = EncryptUtil.encrypt_json(app_data, "thisIsASecretKey")
        print(app_data)
        # 发送到队列
        self.__mq.produce_app_info(encrypted_app_data)
        print("app数据探测结束！")
