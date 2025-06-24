import json

import pika
from retry import retry
from work.AppRiskDetect import AppRiskDetect
from work.AssetsDetect import AssetsDetect
from util.EncryptUtil import EncryptUtil
from work.HotfixDetect import HotfixDetect
from system.SystemInfo import SystemInfo
from work.VulnerabilityDetect import VulnerabilityDetect
from work.WeakPasswordDetect import WeakPasswordDetect
from work.RiskDetect import RiskDetect

class RabbitMQ:
    def __init__(self):
        self.__host  = "47.92.120.180"
        self.__port  = "4568"
        self.__user  = "admin"
        self.__password = "20250606"
        self.__virtual_host = "my_vhost"
        self.__channel = ""
        self.__connection = ""
              # 将连接参数保存为实例属性
        self._connection_params = pika.ConnectionParameters(
            host=self.__host,
            port=self.__port,
            virtual_host=self.__virtual_host,
            credentials=pika.PlainCredentials(self.__user, self.__password)
        )
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
        try:
            self.__connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.__host,
                                    port=self.__port,
                                    virtual_host=self.__virtual_host,
                                    credentials=credentials))
        except Exception as e:
                print(f"RabbitMQ 连接失败: {e}")
                raise
        # 获取通道
        self.__channel = self.__connection.channel()

    def __my_producer(self, exchange, routing_key, data):
        if not isinstance(data, (str, bytes)):
            print(f"[ERROR] 发送数据类型错误: {type(data)}，内容: {data}")
            return
        try:
            self.__channel.basic_publish(exchange=exchange, routing_key=routing_key, body=data)
        except Exception as e:
            print(f"[ERROR] 发送消息失败: {e}")
            if "Channel is closed" in str(e):
                self._reconnect()

    def __process_message(self, ch, method, properties, message):
        msg_str = message.decode('utf-8')
        print("收到消息内容:", msg_str)
        try:
            data = json.loads(msg_str)
        except Exception:
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
            weakPassword_detect = WeakPasswordDetect(self, data)
            weakPassword_detect.start()
            weakPassword_detect.join()

            if weakPassword_detect.found:
                print("✅ 已发现弱口令！")
            else:
                print("❌ 没有发现弱口令")

        elif data['type'] == 'log':
            # 【修改点】在这里进行本地导入
            if SystemInfo().is_windows():
                from work.LogDetectWin import LogDetect
            else:
                from work.LogDetectLinux import LogDetect

            mac_address = data.get('macAddress')
            start_time = data.get('start_time')
            end_time = data.get('end_time')
            limit = data.get('limit', 200)
            log_detect = LogDetect(mac_address, start_time, end_time, limit=limit)
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



    # 假设在某个类中
    @retry(exceptions=Exception, delay=2, backoff=2, max_delay=60)
    def consume_queue(self, queue_name):
        try:
            # 确保队列存在
            self.__channel.queue_declare(queue=queue_name, durable=True)
            # 绑定到 agent_exchange，routing_key 可用队列名或自定义
            self.__channel.queue_bind(
                exchange='agent_exchange',
                queue=queue_name,
                routing_key=queue_name.replace("agent_", "").replace("_queue", "")
            )
            self.__channel.basic_consume(
                queue=queue_name,
                on_message_callback=self.__process_message,
                auto_ack=True
            )
            self.__channel.start_consuming()
        except Exception as e:
            print(f"[!] 消费队列时发生异常: {e}")
            raise


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

    def _reconnect(self):
        try:
            # 使用 self.__connection 替代 self._connection
            if hasattr(self, '_RabbitMQ__connection') and self.__connection:
                try:
                    self.__connection.close()
                except Exception:
                    pass
            # 重新建立连接
            self.__connection = pika.BlockingConnection(self._connection_params)
            # 重新建立 channel，使用 self.__channel 替代 self._channel
            self.__channel = self.__connection.channel()
            print("[INFO] RabbitMQ 连接和 channel 已重新建立")
        except Exception as e:
            print(f"[ERROR] RabbitMQ 重连失败: {e}")
            self.__connection = None
            self.__channel = None