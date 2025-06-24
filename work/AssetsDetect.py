import json
import threading
import platform
import psutil
from util.EncryptUtil import EncryptUtil

# Windows 专用库
if platform.system() == "Windows":
    import winreg
    import pythoncom
    import wmi
    from nmap import nmap


class AssetsDetect(threading.Thread):
    """
    资产探测的线程类，支持 Windows 和 Linux
    """
    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data
        self.__is_windows = platform.system() == "Windows"

    def run(self):
        """
        线程运行函数
        """
        self.__detect()

    def __detect(self):
        """
        探测的方法
        """
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

        if app == 1 and self.__is_windows:
            self.__detect_app()

    def __detect_account(self):
        """
        探测账号资产
        """
        if self.__is_windows:
            # Windows 账号探测
            pythoncom.CoInitialize()
            c = wmi.WMI()
            account_list = []
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
            pythoncom.CoUninitialize()
        else:
            # Linux 账号探测
            account_list = []
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        parts = line.split(":")
                        account_list.append({
                            "macAddress": self.__data['macAddress'],
                            "name": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6].strip()
                        })
            except FileNotFoundError:
                print("[!] 无法读取 /etc/passwd 文件")

        account_data = json.dumps(account_list)
        encrypted_account_data = EncryptUtil.encrypt_json(account_data, "thisIsASecretKey")
        print(account_data)
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_account_info(encrypted_account_data)

    def __detect_service(self):
        """
        探测服务资产
        """
        service_list = []
        if self.__is_windows:
            # Windows 服务探测
            nm = nmap.PortScanner()
            nm.scan(hosts='127.0.0.1', arguments='-sTV')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service_list.append({
                            'macAddress': self.__data['macAddress'],
                            'protocol': proto,
                            'port': port,
                            'state': nm[host][proto][port]['state'],
                            'name': nm[host][proto][port]['name'],
                            'product': nm[host][proto][port]['product'],
                            'version': nm[host][proto][port]['version'],
                            'extraInfo': nm[host][proto][port].get('extraInfo', 'N/A')
                        })
        else:
            # Linux 服务探测
            try:
                with open("/etc/services", "r") as f:
                    for line in f:
                        if not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                service_list.append({
                                    "macAddress": self.__data['macAddress'],
                                    "name": parts[0],
                                    "port_protocol": parts[1]
                                })
            except FileNotFoundError:
                print("[!] 无法读取 /etc/services 文件")

        service_data = json.dumps(service_list)
        encrypted_service_data = EncryptUtil.encrypt_json(service_data, "thisIsASecretKey")
        print(service_data)
        self.__mq.produce_service_info(encrypted_service_data)

    def __detect_process(self):
        """
        探测进程资产
        """
        process_list = []
        if self.__is_windows:
            # Windows 进程探测
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for process in c.Win32_Process():
                process_list.append({
                    'macAddress': self.__data['macAddress'],
                    'pid': process.ProcessId,
                    'ppid': process.ParentProcessId,
                    'name': process.Name,
                    'cmd': process.CommandLine,
                    'priority': process.Priority,
                    'description': process.Description,
                })
            pythoncom.CoUninitialize()
        else:
            # Linux 进程探测
            for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "cmdline"]):
                process_list.append({
                    "macAddress": self.__data['macAddress'],
                    "pid": proc.info["pid"],
                    "ppid": proc.info["ppid"],
                    "name": proc.info["name"],
                    "cmd": " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
                })

        process_data = json.dumps(process_list)
        encrypted_process_data = EncryptUtil.encrypt_json(process_data, "thisIsASecretKey")
        print(process_data)
        self.__mq.produce_process_info(encrypted_process_data)

    def __detect_app(self):
        """
        探测应用资产（仅适用于 Windows）
        """
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
        software_list = []
        number = winreg.QueryInfoKey(registry_key)[0]
        for i in range(number):
            try:
                sub_key_name = winreg.EnumKey(registry_key, i)
                sub_key = winreg.OpenKey(registry_key, sub_key_name)
                software = {}
                try:
                    software['macAddress'] = self.__data['macAddress']
                    software['displayName'] = winreg.QueryValueEx(sub_key, 'DisplayName')[0]
                    software['installLocation'] = winreg.QueryValueEx(sub_key, 'InstallLocation')[0]
                    software['uninstallString'] = winreg.QueryValueEx(sub_key, 'UninstallString')[0]
                    software_list.append(software)
                except WindowsError:
                    continue
            except WindowsError:
                break

        app_data = json.dumps(software_list)
        encrypted_app_data = EncryptUtil.encrypt_json(app_data, "thisIsASecretKey")
        print(app_data)
        self.__mq.produce_app_info(encrypted_app_data)