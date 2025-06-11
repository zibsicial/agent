import json
import threading
import time


class HeartCheck(threading.Thread):
    def __init__(self,mac_address,mq):

        super().__init__()

        self.__mac_address = mac_address
        self.__mq = mq


    def run(self):
        #组装数据
        status_data = {
            "mac_address": self.__mac_address,
            "status": 1
        }
        #转换为JSON
        status_data = json.dumps(status_data)

        while True:
            try:
                #发送心跳包
                self.__mq.produce_status_info(status_data)
                #休眠3秒
                time.sleep(3)
            except  Exception as e:
                print("发送心跳包异常:",e)
                break

    def stop(self):
        self.running  = False