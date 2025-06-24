import threading
import json
import time
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom
from util.EncryptUtil import EncryptUtil
from mq.RabbitMQ import RabbitMQ  # 导入RabbitMQ类
from datetime import datetime
from dateutil import parser as dt_parser


class LogDetect(threading.Thread):
    # 1. 修改构造函数，与Linux版本保持一致
    def __init__(self, mac_address, start_time=None, end_time=None, limit=None, page=1):
        super().__init__()
        self.__event_path = r"C:\Windows\system32\winevt\Logs\Security.evtx"
        self.__mac_address = mac_address
        self.__start_time = start_time
        self.__end_time = end_time
        self.__limit = limit  # 保存limit参数
        self.__page = page
        self.running = True
        self.__event_ids = [
            4624, 4634, 4647, 4648, 4720, 4722, 4723, 4724,
            4726, 4725, 4738, 4730, 4737, 4739, 4762, 4732
        ]

    def run(self):
        # 2. 在线程内部创建自己的 RabbitMQ 连接实例
        try:
            mq_instance = RabbitMQ()
        except Exception as e:
            print(f"[ERROR] 日志探测线程(Win)无法连接到RabbitMQ，线程退出: {e}")
            return

        while self.running:
            logs = self.get_log_info(
                self.__event_path,
                event_ids=self.__event_ids,
                start_time=self.__start_time,
                end_time=self.__end_time,
                limit=self.__limit,
                page=self.__page
            )
            for log in logs:
                log['macAddress'] = self.__mac_address
                data = json.dumps(log, ensure_ascii=False, default=str)

                print(f"准备发送(Win)日志: {data}")
                encrypted = EncryptUtil.encrypt_json(data, "thisIsASecretKey")

                # 3. 使用本线程专属的 mq_instance 对象发送消息
                try:
                    mq_instance.produce_log_info(encrypted)
                    print("发送(Win)日志成功！")
                except Exception as e:
                    print(f"[ERROR] 在LogDetect(Win)线程中发送消息失败: {e}")

            # 与Linux版本保持一致，执行一次后退出循环
            break

    def stop(self):
        self.running = False

    def get_log_info(self, event_path, **kwargs):
        event_ids = kwargs.get('event_ids')
        start_time = self.safe_parse_time(kwargs.get('start_time'))
        end_time = self.safe_parse_time(kwargs.get('end_time'))
        limit = kwargs.get('limit', 1000)
        page = kwargs.get('page', 1)

        parser = PyEvtxParser(event_path)
        pattern = re.compile(r'<EventID>(\d+)</EventID>')
        event_list = []

        for record in parser.records():
            xml_data = record['data']
            res = re.findall(pattern, xml_data)
            if not res:
                continue

            try:
                event_id = int(res[0].strip())
            except Exception:
                continue

            record_timestamp = self.safe_parse_time(record['timestamp'])
            if record_timestamp is None:
                continue

            if start_time is not None and record_timestamp < start_time:
                continue
            if end_time is not None and record_timestamp > end_time:
                continue

            if event_ids is not None and event_id in [int(eid) for eid in event_ids]:
                r = {}
                r['event_id'] = event_id
                r['timestamp'] = record_timestamp.strftime("%Y-%m-%d %H:%M:%S")
                try:
                    xml_doc = minidom.parseString(xml_data)
                    data = xml_doc.getElementsByTagName('Data')
                    for d in data:
                        try:
                            name = d.getAttribute('Name')
                            value = html.unescape(d.childNodes[0].data)
                            r[name] = value
                        except Exception:
                            pass
                except Exception as e:
                    print("XML 解析错误：", e)
                    continue
                event_list.append(r)

        # 分页切片
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        return event_list[start_idx:end_idx]

    @staticmethod
    def safe_parse_time(ts):
        if ts is None: return None
        if isinstance(ts, datetime): return ts.replace(tzinfo=None)
        if isinstance(ts, str):
            try:
                return dt_parser.parse(ts).replace(tzinfo=None)
            except:
                return None
        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts)
            except:
                return None
        return None