import json

import pika

from work.AppRiskDetect import AppRiskDetect
from work.AssetsDetect import AssetsDetect
from util.EncryptUtil import EncryptUtil
from work.HotfixDetect import HotfixDetect
from work.LogDetect import LogDetect
from work.VulnerabilityDetect import VulnerabilityDetect
from work.WeakPasswordDetect import WeakPasswordDetect
from work.RiskDetect import RiskDetect

class RabbitMQ:
    def __init__(self):

        self.__host  = "192.168.133.133"

        self.__port  = "4568"
        self.__user  = "admin"
        self.__password = "20250606"
        self.__virtual_host = "my_vhost"
        self.__channel = ""
        self.__connection = ""

        # 初始化连接
        self.__get_connection()

    def __get_connection(self):
        """
        获取连接对象
        :return:
        """
        # 获取认证对象
        credentials = pika.PlainCredentials(self.__user, self.__password)
        # 获取连接
        self.__connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.__host,
                                      port=self.__port,
                                      virtual_host=self.__virtual_host,
                                      credentials=credentials))
        # 获取通道
        self.__channel = self.__connection.channel()

    def __my_producer(self, exchange, routing_key, data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        self.__channel.basic_publish(exchange=exchange, routing_key=routing_key, body=data)

    def __process_message(self, ch, method, properties, message):
        msg_str = message.decode('utf-8')
        print("收到消息内容:", msg_str)
        try:
            # 尝试直接解析为 JSON
            data = json.loads(msg_str)
        except Exception:
            # 如果不是 JSON，说明是加密数据，先解密再解析
            decrypted = EncryptUtil.decrypt_json(msg_str, "thisIsASecretKey")
            data = json.loads(decrypted)

        if data['type'] == 'assets':
            assets_detect = AssetsDetect(self, data)
            assets_detect.start()
        if data['type'] == 'hotfix':
            hotfix_detect = HotfixDetect(self, data)
            hotfix_detect.start()
        if data['type'] == 'risk':
            # 风险探测
            risk_detect = RiskDetect(self, data)
            risk_detect.start()
        if data['type'] == 'vulnerability':
            # 漏洞探测
            vulnerability_detect = VulnerabilityDetect(self, data)
            vulnerability_detect.start()
        elif data['type'] == 'appRisk':
            # 应用风险探测
            appRiskDetect = AppRiskDetect(self, data)
            #线程类直接start
            appRiskDetect.start()
        elif data['type'] == 'weakPassword':
            # 补丁探测
            weakPassword_detect = WeakPasswordDetect(self, data)
            weakPassword_detect.start()

        elif data['type'] == 'log':
            # 登录日志
            # data 里应包含 mac_address、start_time、end_time
            mac_address = data.get('mac_address')
            start_time = data.get('start_time')
            end_time = data.get('end_time')
            log_detect = LogDetect(self, mac_address, start_time, end_time)
            log_detect.start()





    def produce_sysinfo(self, data):
        """
        生产系统信息
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'sysinfo'
        # 发送数据
        self.__my_producer(exchange, routing_key, data)

    def produce_status_info(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'status'
        self.__my_producer(exchange,routing_key,data)

    #登录日志
    def produce_log_info(self, data):
        """
        发送登录日志到 log_queue
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'log'
        self.__my_producer(exchange, routing_key, data)

    #变更日志
    def produce_change_info(self, data):
        """
        发送账号变更日志到 change_queue
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'change_queue'
        self.__my_producer(exchange, routing_key, data)


    #新建一个消费来自MQ的方法
    def consume_queue(self,  queue_name):
        """
        消费者
        :param queue_name: 队列名
        :return:
        """
        # 消费队列
        self.__channel.basic_consume(queue=queue_name,on_message_callback=self.__process_message, auto_ack=True)
        # 开始监听
        self.__channel.start_consuming()


    def produce_account_info(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'account'
        self.__my_producer(exchange,routing_key,data)


    def produce_service_info(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'service'
        self.__my_producer(exchange,routing_key,data)

    def produce_process_info(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'process'
        self.__my_producer(exchange,routing_key,data)

    def produce_app_info(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'app'
        self.__my_producer(exchange,routing_key,data)

    def produce_hotfix_data(self,data):
        """
        生产者
        :param routing_key: 路由键
        :param exchange: 交换机
        :param data: 数据
        :return:
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'hotfix'
        self.__my_producer(exchange,routing_key,data)

    def produce_risk_data(self, data):
        """
        生产风险检测数据
        :param data: 风险检测结果（JSON字符串）
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'risk'
        self.__my_producer(exchange, routing_key, data)

    def produce_appRisk_info(self, data):
        """
        应用信息上报（发到 sysinfo_exchange，routing_key = appRisk）
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'appRisk'
        self.__my_producer(exchange, routing_key, data)


    def produce_weakPassword_data(self, data):
        exchange = 'sysinfo_exchange'
        routing_key = 'weakPassword'
        self.__my_producer(exchange, routing_key, data)

    def produce_vulnerability_data(self, data):

        """
        漏洞检测数据上报
        :param data: 漏洞检测结果（JSON字符串）
        """
        exchange = 'sysinfo_exchange'
        routing_key = 'vulnerability'
        self.__my_producer(exchange, routing_key, data)
