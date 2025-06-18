
# coding=utf-8
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom

def get_log_info(event_path, **kwargs):
    """
    过滤自己想要的日志
    :param event_path: 日志的路径
    :param kwargs: 过滤条件
    :return:
    """
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
        elif event_id_param is None:
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

if __name__ == '__main__':
    # 指定EVTX文件路径
    path = r"C:\Windows\system32\winevt\Logs\Security.evtx"
    # event_list = get_log_info(
    #     path,
    #     event_id=4624,
    #     start_time='2025-06-12 07:24:15',
    #     end_time='2025-06-12 09:04:19'
    # )
    event_list = get_log_info(path,event_id=4624)
    for event in event_list:
        print(event)