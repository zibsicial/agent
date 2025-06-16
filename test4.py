import winreg
import json
print('开始探测app数据......!')
registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
software_list = []
    # 获取软件数量
number = winreg.QueryInfoKey(registry_key)[0]
for i in range(number):
    try:
        sub_key_name = winreg.EnumKey(registry_key, i)
        sub_key = winreg.OpenKey(registry_key, sub_key_name)
        software = {}
        try:
            # software['mac'] = self.__data['mac']
            software['display_name'] = winreg.QueryValueEx(sub_key,'DisplayName')[0]
            software['install_location'] = winreg.QueryValueEx(sub_key,'InstallLocation')[0]
            software['uninstall_string'] = winreg.QueryValueEx(sub_key,'UninstallString')[0]
            software_list.append(software)
        except WindowsError:
            continue
    except WindowsError:
        break
    # 转换成JSON字符串
app_data = json.dumps(software_list)
print(app_data)
# 发送到队列
#self.__mq.produce_app_info(app_data)
print("app数据探测结束！")