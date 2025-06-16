import pythoncom
import wmi
import json
print("开始补丁安全发现......!")
# 初始化
#pythoncom.CoInitialize()
# 创建WMI客户端
c = wmi.WMI()
# 获取补丁信息
hotfixes = c.query("SELECT HotFixID FROM Win32_QuickFixEngineering")
# 组装补丁ID
hotfix_list = []
for hotfix in hotfixes:
    data = {
        #'macAddress': self.__data['macAddress'],
        'hotfixId': hotfix.HotFixID
    }
    hotfix_list.append(data)
# 去初始化
#pythoncom.CoUninitialize()
# 转换成JSON数据
data = json.dumps(hotfix_list)
print(data)
# 发送到队列
#self.__mq.produce_hotfix_data(data)
print("补丁安全发现结束")