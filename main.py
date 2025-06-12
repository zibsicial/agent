
from system.SystemInfo import SystemInfo
from mq.RabbitMQ import RabbitMQ
from work.HeartCheck import HeartCheck
from work.ReceiveCmd import ReceiveCmd


if __name__ == '__main__':

    print("Agent启动................")
    print("Agent开始获取系统信息.....")

    #实例化这个类
    sys_info = SystemInfo()
    sys_info_data = sys_info.get_info()


    print("Agent开始同步系统信息.....")

    #实例化MQ
    rabbitmq = RabbitMQ()
    rabbitmq.produce_sysinfo(sys_info_data)
    print(sys_info_data)

    print("Agent同步系统信息结束.....")
    #获取MAC地址
    mac_address = sys_info.get_mac_address()
    #实例化心跳检测类
    heartcheck = HeartCheck(mac_address,rabbitmq)
    heartcheck.start()

    print("Agent准备接收信息... ")
    rabbitmq = RabbitMQ()
    recevie_cmd = ReceiveCmd(rabbitmq,mac_address)
    recevie_cmd.start()
