import json
import threading
import pymysql
import pythoncom
import wmi
import win32security
import redis
from ftplib import FTP
import pymongo
from pymongo.errors import OperationFailure


class WeakPasswordDetect(threading.Thread):
    """
    弱口令探测类
    """

    COMMON_PASSWORDS = [
        '123456', '12345678', '123456789', '1234567890', '111111', '000000', '123123',
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
        """
        检测 MySQL 弱口令
        """
        weak_mysql = []
        users = ['root', 'admin']
        passwords = [
            '123456', '12345678', '123456789', '1234567890', '111111', '000000', '123123',
            'password', 'admin', 'root', 'qwerty', 'abc123', '1qaz2wsx', 'asdfgh',
            'letmein', 'welcome', 'passw0rd', 'dragon', 'monkey', 'login', 'master',
            '654321', 'superman', 'qwertyuiop', 'test', 'hello', 'iloveyou', '1234', '121212', '987654321'
        ]

        for user in users:
            for pwd in passwords:
                try:
                    conn = pymysql.connect(
                        host=ip,
                        user=user,
                        password=pwd,
                        port=port,
                        connect_timeout=3
                    )
                    weak_mysql.append((user, pwd))
                    conn.close()
                    break
                except Exception:
                    continue
        return weak_mysql

    def __check_local_account_weak_password(self):
        """
        检测本地系统账户弱口令
        """
        weak_accounts = []
        c = wmi.WMI()
        for user in c.Win32_UserAccount(LocalAccount=True):
            username = user.Name
            for pwd in self.COMMON_PASSWORDS:
                try:
                    win32security.LogonUser(
                        username,
                        None,
                        pwd,
                        win32security.LOGON32_LOGON_INTERACTIVE,
                        win32security.LOGON32_PROVIDER_DEFAULT
                    )
                    weak_accounts.append((username, pwd))
                    break
                except Exception:
                    continue
        return weak_accounts


    def __check_ftp_weak_password(self, host="127.0.0.1"):
        weak_ftp = []
        users = ['ftp', 'admin', 'test', 'anonymous']
        passwords = self.COMMON_PASSWORDS
        for user in users:
            for pwd in passwords:
                try:
                    ftp = FTP()
                    ftp.connect(host, 21, timeout=3)
                    ftp.login(user, pwd)
                    weak_ftp.append((user, pwd))
                    ftp.quit()
                    break
                except:
                    continue
        return weak_ftp


    def __check_mongodb_weak_password(self, host="127.0.0.1", port=27017):
        weak_mongo = []
        users = ['admin', 'root']
        passwords = self.COMMON_PASSWORDS
        for user in users:
            for pwd in passwords:
                try:
                    uri = f"mongodb://{user}:{pwd}@{host}:{port}/admin"
                    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=3000)
                    client.admin.command('ping')
                    weak_mongo.append((user, pwd))
                    break
                except OperationFailure:
                    continue
                except:
                    continue
        return weak_mongo

    def __check_redis_weak_password(self, host="127.0.0.1", port=6379):
        weak_redis = []
        passwords = self.COMMON_PASSWORDS
        for pwd in passwords:
            try:
                r = redis.StrictRedis(host=host, port=port, password=pwd, socket_connect_timeout=2)
                r.ping()
                weak_redis.append(('redis', pwd))
                break
            except:
                continue
        return weak_redis

    def __weakPassword_discovery(self):
        """
        弱口令探测主流程
        """
        print("开始弱密码探测")
        pythoncom.CoInitialize()

        weakPassword_list = []

        # 探测本地账户弱口令
        account_result = self.__check_local_account_weak_password()
        print("[DEBUG] local_account_result =", account_result)
        for user, pwd in account_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'LocalAccount',
                'username': user,
                'password': pwd,
            })

        # Redis 弱口令探测
        redis_result = self.__check_redis_weak_password()
        for user, pwd in redis_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'Redis',
                'username': user,
                'password': pwd,
            })

        # FTP 弱口令探测
        ftp_result = self.__check_ftp_weak_password()
        for user, pwd in ftp_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'FTP',
                'username': user,
                'password': pwd,
            })

        # MongoDB 弱口令探测
        mongo_result = self.__check_mongodb_weak_password()
        for user, pwd in mongo_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'MongoDB',
                'username': user,
                'password': pwd,
            })

        # 探测 MySQL 弱口令
        mysql_result = self.__check_mysql_weak_password(ip="127.0.0.1", port=3306)
        print("[DEBUG] mysql_result =", mysql_result)
        for user, pwd in mysql_result:
            weakPassword_list.append({
                'macAddress': self.__data['macAddress'],
                'account_type': 'MySQL',
                'username': user,
                'password': pwd,
            })

        pythoncom.CoUninitialize()

        # 发送结果
        weakPassword_data = json.dumps(weakPassword_list)
        self.__mq.produce_weakPassword_data(weakPassword_data)
        print("弱口令探测完成")
