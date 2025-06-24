import threading
import json
import time
import re
import subprocess
import os
from util.EncryptUtil import EncryptUtil
from mq.RabbitMQ import RabbitMQ  # 导入RabbitMQ类
from datetime import datetime
from dateutil import parser as dt_parser

os.environ.pop('LD_LIBRARY_PATH', None)


class LogDetect(threading.Thread):
    # 1. 构造函数不再接收 mq 对象
    def __init__(self, mac_address, start_time=None, end_time=None, limit=200, page=1):
        super().__init__()
        self.__mac_address = mac_address
        self.__start_time = start_time
        self.__end_time = end_time
        self.__limit = limit
        self.__page = page
        self.running = True
        # 只保留最关键的安全事件关键字
        self.__event_keywords = [
            "Accepted password", "Failed password", "authentication failure",
            "useradd", "usermod", "userdel", "sudo", "su"
        ]

    def run(self):
        # 2. 在线程内部创建自己的 RabbitMQ 连接实例
        try:
            mq_instance = RabbitMQ()
        except Exception as e:
            print(f"[ERROR] 日志探测线程无法连接到RabbitMQ，线程退出: {e}")
            return

        while self.running:
            logs = self.get_log_info(
                event_keywords=self.__event_keywords,
                start_time=self.__start_time,
                end_time=self.__end_time,
                limit=200,  # 强制100
                page=self.__page
            )
            for log in logs:
                log['macAddress'] = self.__mac_address
                data = json.dumps(log, ensure_ascii=False, default=str)
                encrypted = EncryptUtil.encrypt_json(data, "thisIsASecretKey")

                print(f"准备发送日志: {data}")

                # 3. 使用本线程专属的 mq_instance 对象发送消息
                try:
                    mq_instance.produce_log_info(encrypted)
                    print("发送日志成功！")
                except Exception as e:
                    print(f"[ERROR] 在LogDetect线程中发送消息失败: {e}")
                    # 可以在这里添加重连逻辑或让pika的内部重连机制处理

            # 注意：一次性任务不应该在while循环里。如果这是由命令触发的一次性任务，应该在发送后退出循环。
            # 这里暂时保留循环，但添加 break，使其执行一次后就退出。
            # 如果需要持续监控，请移除下面的 break。
            break

    def stop(self):
        self.running = False

    def get_log_info(self, event_keywords, start_time=None, end_time=None, limit=200, page=1, max_count=1000):
        event_list = []
        # 只查 sshd 服务
        cmd = [
            "journalctl", "--no-pager", "--quiet", "--output=short",
            "-u", "sshd", "-n", "200"
        ]
        if start_time:
            cmd += ["--since", self._format_time(start_time)]
        if end_time:
            cmd += ["--until", self._format_time(end_time)]

        env = os.environ.copy()
        env.pop('LD_LIBRARY_PATH', None)

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", timeout=10,
                                    env=env)
            print("STDOUT:")
            print(result.stdout)
            print("STDERR:")
            print(result.stderr)
            for line in result.stdout.splitlines():
                if any(keyword in line for keyword in event_keywords):
                    event = {
                        "timestamp": self.extract_timestamp(line).strftime("%Y-%m-%d %H:%M:%S"),
                        "log": line.strip()
                    }
                    event_list.append(event)
        except Exception as e:
            print("调用 journalctl 失败：", e)
        return event_list

    @staticmethod
    def extract_timestamp(log_line):
        try:
            match = re.match(r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", log_line)
            if match:
                timestamp_str = match.group(1)
                return dt_parser.parse(timestamp_str, fuzzy=True)
        except Exception as e:
            print(f"[!] 无法解析日志时间戳: {log_line}", e)
        return None

    @staticmethod
    def _format_time(ts):
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(ts, str):
            try:
                return dt_parser.parse(ts).strftime("%Y-%m-%d %H:%M:%S")
            except:
                return ts
        if isinstance(ts, (int, float)):
            try:
                dt = datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                return str(ts)
        return str(ts)


print("LANG:", os.environ.get("LANG"))
print("LC_ALL:", os.environ.get("LC_ALL"))
