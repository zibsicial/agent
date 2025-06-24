import json
import threading
import platform

# Windows 专用库
if platform.system() == "Windows":
    import pythoncom
    import wmi
    import win32security


class WeakPasswordDetect(threading.Thread):
    """
    弱口令探测类（仅本地）
    """

    COMMON_PASSWORDS = [
        '123456', '123456789', '1234567890', '111111', '000000', '123123', '2022-06-06',
        'password', 'admin', 'root', 'qwerty', 'abc123', '1qaz2wsx', 'asdfgh',
        'letmein', 'welcome', 'passw0rd', 'dragon', 'monkey', 'login', 'master',
        '654321', 'superman', 'qwertyuiop', 'test', 'hello', 'iloveyou', '1234', '121212', '987654321'
    ]

    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data
        self.finished = False
        self.found = False
        self.__is_windows = platform.system() == "Windows"

    def run(self):
        self.__weakPassword_discovery()
        self.finished = True

    def __check_local_account_weak_password(self):
        weak_accounts = []
        if self.__is_windows:
            # 在Windows上检查本地账户弱口令
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for user in c.Win32_UserAccount(LocalAccount=True):
                username = user.Name
                for pwd in self.COMMON_PASSWORDS:
                    try:
                        win32security.LogonUser(
                            username, None, pwd,
                            win32security.LOGON32_LOGON_INTERACTIVE,
                            win32security.LOGON32_PROVIDER_DEFAULT
                        )
                        weak_accounts.append((username, pwd))
                        break
                    except Exception:
                        continue
            pythoncom.CoUninitialize()
        else:
            # 在Linux上通过/etc/passwd检查弱口令 (这是一个简化检查)
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        username = line.split(":")[0]
                        for pwd in self.COMMON_PASSWORDS:
                            if username == pwd:
                                weak_accounts.append((username, pwd))
                                break
            except FileNotFoundError:
                print("[!] 无法读取 /etc/passwd 文件")
        return weak_accounts

    def __weakPassword_discovery(self):
        print("[INFO] 本机弱口令探测开始")
        weakPassword_list = []

        # 检查本地账户
        local_result = self.__check_local_account_weak_password()
        for user, pwd in local_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'LocalAccount',
                'username': user,
                'password': pwd,
                'ip': '127.0.0.1',
                'port': 0
            })

        if weakPassword_list:
            self.found = True

        # 按要求保留，将结果通过RabbitMQ发送
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_weakPassword_data(json.dumps(weakPassword_list, ensure_ascii=False))
        print("[INFO] 本机弱口令探测完成")
