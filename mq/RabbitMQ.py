import json

import pika

from work.AssetsDetect import AssetsDetect
from util.EncryptUtil import EncryptUtil

class RabbitMQ:
    def __init__(self):
        self.__host  = "192.168.169.134"
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
        """
        处理消息
        :param ch:
        :param properties:
        :param message:
        :return:
        """

        # 解密消息
        message = EncryptUtil.decrypt_json(message.decode('utf-8'), "thisIsASecretKey")
        # JSON字符串转换成字典
        data = json.loads(message)
        # print(data)
        # 判断类型
        if data['type'] == 'assets':
            # 资产探测
            assetsDetect = AssetsDetect(self, data)
            assetsDetect.start()


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

