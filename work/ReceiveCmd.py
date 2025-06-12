import threading


class ReceiveCmd(threading.Thread):
    """
    专用于接收平台发送的指令的类
    """
    def __init__(self,mq,mac_address):
        super().__init__()
        #mq对象
        self.__mq = mq
        #MAC地址用于匹配队列名
        self.__mac_address = mac_address

    def run(self):
        #组装队列名字，格式为：agent_[mac_address(去除：)]_queue
        queue_name = "agent_" + self.__mac_address.replace(":","") + "_queue"
        print("接收指令的队列名:", queue_name)
        #获取队列
        self.__mq.consume_queue(queue_name)