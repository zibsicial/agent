
import threading
import json
import time
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom
from util.EncryptUtil import EncryptUtil

class LogDetect(threading.Thread):
    def __init__(self, mq, mac_address, start_time=None, end_time=None):
        super().__init__()
        self.__mq = mq
        self.__event_path = r"C:\Windows\system32\winevt\Logs\Security.evtx"
        self.__mac_address = mac_address
        self.__start_time = start_time
        self.__end_time = end_time
        self.running = True

    def run(self):
        while self.running:
            logs = self.get_log_info(
                self.__event_path,
                event_id=4624,
                start_time=self.__start_time,
                end_time=self.__end_time
            )
            for log in logs:
                log['macAddress'] = self.__mac_address
                data = json.dumps(log, ensure_ascii=False)
                print("即将发送的登录日志：", data)  # 控制台输出
                encrypted = EncryptUtil.encrypt_json(data, "thisIsASecretKey")
                print(encrypted)
                self.__mq.produce_log_info(encrypted)
                print("发送日志成功！！！")
            time.sleep(60)  # 每分钟同步一次

    def stop(self):
        self.running = False

    def get_log_info(self, event_path, **kwargs):
        event_id_param = kwargs.get('event_id')
        start_time = kwargs.get('start_time')
        end_time = kwargs.get('end_time')
        parser = PyEvtxParser(event_path)
        pattern = re.compile(r'<EventID>(\d+)</EventID>')
        event_list = []
        for record in parser.records():
            xml_data = record['data']
            res = re.findall(pattern, xml_data)
            if not res:
                continue
            event_id = int(res[0])
            if start_time is not None and record['timestamp'] < start_time:
                continue
            if end_time is not None and record['timestamp'] > end_time:
                continue
            if event_id_param is not None and event_id == event_id_param:
                r = {}
                r['event_id'] = event_id
                r['timestamp'] = record['timestamp']
                xml_doc = minidom.parseString(xml_data)
                data = xml_doc.getElementsByTagName('Data')
                for d in data:
                    try:
                        name = d.getAttribute('Name')
                        value = html.unescape(d.childNodes[0].data)
                        r[name] = value
                    except Exception:
                        pass
                event_list.append(r)
        return event_list