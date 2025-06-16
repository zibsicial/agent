import nmap
import json
print('开始探测服务数据......!')
    # 创建一个扫描仪对象



nm = nmap.PortScanner()
# 扫描目标主机
nm.scan(hosts='172.16.113.70', arguments='-sTV')  # 指定扫描端口范围
# 获取扫描结果
state = nm.all_hosts()
# 装最终结果的
res_list = []
if state:
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                # 接收nmap扫描结果
                nmap_res = {
                    # 'mac': self.__data['mac'],
                    'protocol': proto,
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port]['product'],
                    'version': nm[host][proto][port]['version'],
                    'extrainfo': nm[host][proto][port]['extrainfo']}
                res_list.append(nmap_res)
# 转换成JSON字符串
res_json = json.dumps(res_list)

# 发送到队列
# self.__mq.produce_service_data(res_json)

print('开始探测服务数据......!')
    # 创建一个扫描仪对象



nm = nmap.PortScanner()
# 扫描目标主机
nm.scan(hosts='172.16.113.70', arguments='-sTV')  # 指定扫描端口范围
# 获取扫描结果
state = nm.all_hosts()
# 装最终结果的
res_list = []
if state:
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                # 接收nmap扫描结果
                nmap_res = {
                    # 'mac': self.__data['mac'],
                    'protocol': proto,
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port]['product'],
                    'version': nm[host][proto][port]['version'],
                    'extrainfo': nm[host][proto][port]['extrainfo']}
                res_list.append(nmap_res)
# 转换成JSON字符串
res_json = json.dumps(res_list)

# 发送到队列
# self.__mq.produce_service_data(res_json)
if res_list:
    print("扫描成功，结果如下：")
    print(json.dumps(res_list, indent=2, ensure_ascii=False))
else:
    print("未扫描到任何服务或端口。")

print("服务数据探测结束！")