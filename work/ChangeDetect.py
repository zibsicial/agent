
# work/ChangeDetect.py
import threading
import json
import time
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom
from util.EncryptUtil import EncryptUtil

class ChangeDetect(threading.Thread):
    def __init__(self, mq, event_path, mac_address, start_time=None, end_time=None):
        super().__init__()
        self.__mq = mq
        self.__event_path = event_path
        self.__mac_address = mac_address
        self.__start_time = start_time
        self.__end_time = end_time
        self.running = True

    def run(self):
        while self.running:
            change_event_ids = [4720, 4722, 4723, 4724, 4725, 4726]
            for eid in change_event_ids:
                logs = self.get_log_info(
                    self.__event_path,
                    event_id=eid,
                    start_time=self.__start_time,
                    end_time=self.__end_time
                )
                for log in logs:
                    log['macAddress'] = self.__mac_address
                    data = json.dumps(log)
                    encrypted = EncryptUtil.encrypt_json(data, "thisIsASecretKey")
                    self.__mq.produce_change_info(encrypted)
            time.sleep(86400)  # 每天同步一次

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