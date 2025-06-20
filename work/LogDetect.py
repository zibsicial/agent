
import threading
import json
import time
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom
from util.EncryptUtil import EncryptUtil
from datetime import datetime
from dateutil import parser as dt_parser

class LogDetect(threading.Thread):
    def __init__(self, mq, mac_address, start_time=None, end_time=None):
        super().__init__()
        self.__mq = mq
        self.__event_path = r"C:\Windows\system32\winevt\Logs\Security.evtx"
        self.__mac_address = mac_address
        self.__start_time = start_time
        self.__end_time = end_time
        self.running = True
        # 需要探查的所有事件ID
        self.__event_ids = [
            4624, 4634, 4647, 4648, 4720, 4722, 4723, 4724,
            4726, 4725, 4738, 4730, 4737, 4739, 4762, 4732
        ]

    def run(self):
        while self.running:
            logs = self.get_log_info(
                self.__event_path,
                event_ids=self.__event_ids,
                start_time=self.__start_time,
                end_time=self.__end_time
            )
            for log in logs:
                log['macAddress'] = self.__mac_address
                data = json.dumps(log, ensure_ascii=False, default=str)
                print("即将发送的登录日志：", data)
                encrypted = EncryptUtil.encrypt_json(data, "thisIsASecretKey")
                print(encrypted)
                self.__mq.produce_log_info(encrypted)
                print("发送日志成功！！！")
            # 每分钟同步一次

    def stop(self):
        self.running = False

    def get_log_info(self, event_path, **kwargs):
        event_ids = kwargs.get('event_ids')
        start_time = self.safe_parse_time(kwargs.get('start_time'))
        end_time = self.safe_parse_time(kwargs.get('end_time'))

        parser = PyEvtxParser(event_path)
        pattern = re.compile(r'<EventID>(\d+)</EventID>')
        event_list = []

        for record in parser.records():
            xml_data = record['data']
            res = re.findall(pattern, xml_data)
            if not res:
                continue

            event_id = int(res[0])
            record_timestamp = record['timestamp']

            # 统一将 record_timestamp 解析为 datetime 对象
            record_timestamp = self.safe_parse_time(record_timestamp)
            if record_timestamp is None:
                continue

            if start_time is not None and record_timestamp < start_time:
                continue
            if end_time is not None and record_timestamp > end_time:
                continue


            if event_ids is not None and event_id in event_ids:
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

        return event_list


    @staticmethod
    def safe_parse_time(ts):
        if ts is None:
            return None

        if isinstance(ts, datetime):
            # 去除 tzinfo，变成 naive datetime
            return ts.replace(tzinfo=None)

        if isinstance(ts, str):
            try:
                parsed = dt_parser.parse(ts)
                return parsed.replace(tzinfo=None)  # 转为 naive
            except Exception as e:
                print(f"[!] 无法解析时间字符串: {ts}", e)
                return None

        if isinstance(ts, (int, float)):
            try:
                if ts > 1e12:  # 毫秒时间戳
                    ts = ts / 1000
                return datetime.fromtimestamp(ts)
            except Exception as e:
                print(f"[!] 无法解析时间戳: {ts}", e)
                return None

        return None

