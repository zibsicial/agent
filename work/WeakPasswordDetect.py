import json
import threading
import pymysql
import pythoncom
import wmi
import win32security
import redis
import pika
import subprocess
import socket
import re


class WeakPasswordDetect(threading.Thread):
    """
    弱口令探测类（本地 + MySQL + 虚拟机 Redis/RabbitMQ）
    """

    # 密码字典
    COMMON_PASSWORDS = [
        '123456', '12345678', '123456789', '1234567890', '111111', '000000', '123123', '20250606',
        'password', 'admin', 'root', 'qwerty', 'abc123', '1qaz2wsx', 'asdfgh',
        'letmein', 'welcome', 'passw0rd', 'dragon', 'monkey', 'login', 'master',
        '654321', 'superman', 'qwertyuiop', 'test', 'hello', 'iloveyou', '1234', '121212', '987654321'
    ]

    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data

    def run(self):
        self.__weakPassword_discovery()

    def __check_mysql_weak_password(self, ip="127.0.0.1", port=3306):
        weak_mysql = []
        users = ['root', 'admin']
        for user in users:
            for pwd in self.COMMON_PASSWORDS:
                try:
                    conn = pymysql.connect(host=ip, user=user, password=pwd, port=port, connect_timeout=3)
                    weak_mysql.append((user, pwd))
                    conn.close()
                    break
                except Exception:
                    continue
        return weak_mysql

    def __check_local_account_weak_password(self):
        weak_accounts = []
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
        return weak_accounts

    def __check_port(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=1):
                return True
        except:
            return False

    def __ping_host(self, ip):
        try:
            output = subprocess.check_output(["ping", "-n", "1", "-w", "200", ip], stderr=subprocess.DEVNULL, encoding='gbk')
            return "TTL=" in output
        except:
            return False

    def __get_network_prefix(self):
        try:
            output = subprocess.check_output("ipconfig", encoding='gbk', errors='ignore')
            lines = output.splitlines()
            block, collecting = [], False
            for line in lines:
                if "VMware Network Adapter VMnet8" in line:
                    collecting = True
                    block.append(line)
                    continue
                if collecting:
                    if re.match(r"^\s*.*适配器.*:", line) and "VMware Network Adapter VMnet8" not in line:
                        break
                    block.append(line)
            block_text = "\n".join(block)
            match = re.search(r"IPv4\s*地址.*?[：:]\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)", block_text)
            if match:
                ip = match.group(1)
                return ".".join(ip.split(".")[:3]) + "."
        except Exception as e:
            print(f"[ERROR] 获取虚拟网关失败: {e}")
        return None

    def __brute_force_redis(self, ip, port):
        for pwd in self.COMMON_PASSWORDS:
            try:
                r = redis.StrictRedis(host=ip, port=port, password=pwd, socket_connect_timeout=2)
                r.ping()
                return pwd
            except:
                continue
        return None

    def __brute_force_rabbitmq(self, ip, port, virtual_host='my_vhost'):
        user_list = ['guest', 'admin', 'root']
        password_list = self.COMMON_PASSWORDS

        for username in user_list:
            for password in password_list:
                try:
                    credentials = pika.PlainCredentials(username, password)
                    parameters = pika.ConnectionParameters(
                        host=ip,
                        port=port,
                        virtual_host=virtual_host,
                        credentials=credentials,
                        socket_timeout=3
                    )
                    connection = pika.BlockingConnection(parameters)
                    connection.close()
                    print(f"[SUCCESS] RabbitMQ 弱口令成功: {ip}:{port} -> {username}:{password}")
                    return username, password
                except Exception as e:
                    print(f"[DEBUG] 失败: {username}:{password} -> {e}")
                    continue
        print(f"[INFO] RabbitMQ {ip}:{port} 未发现弱口令")
        return None

    def __weakPassword_discovery(self):
        print("[INFO] 弱口令探测开始")
        pythoncom.CoInitialize()
        weakPassword_list = []

        # 本地账户弱口令
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

        # MySQL 弱口令
        mysql_result = self.__check_mysql_weak_password()
        for user, pwd in mysql_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'MySQL',
                'username': user,
                'password': pwd,
                'ip': '127.0.0.1',
                'port': 3306
            })

        # 虚拟机 Redis / RabbitMQ 弱口令扫描
        prefix = self.__get_network_prefix()
        if prefix:
            live_hosts = [f"{prefix}{i}" for i in range(2, 255) if self.__ping_host(f"{prefix}{i}")]
            print(f"[INFO] 虚拟机存活主机: {live_hosts}")

            for ip in live_hosts:
                if self.__check_port(ip, 6379):
                    pwd = self.__brute_force_redis(ip, 6379)
                    if pwd:
                        weakPassword_list.append({
                            'macAddress': self.__data['macAddress'],
                            'account_type': 'VirtualMachine_Redis',
                            'username': '(default)',
                            'password': pwd,
                            'ip': ip,
                            'port': 6379
                        })

                if self.__check_port(ip, 4568):
                    result = self.__brute_force_rabbitmq(ip, 4568, virtual_host='my_vhost')  # ✅ 添加虚拟主机参数
                    if result:
                        user, pwd = result
                        weakPassword_list.append({
                            'macAddress': self.__data['macAddress'],
                            'account_type': 'VirtualMachine_RabbitMQ',
                            'username': user,
                            'password': pwd,
                            'ip': ip,
                            'port': 4568
                        })

        pythoncom.CoUninitialize()
        self.__mq.produce_weakPassword_data(json.dumps(weakPassword_list, ensure_ascii=False))
        print("[INFO] 弱口令探测完成")
