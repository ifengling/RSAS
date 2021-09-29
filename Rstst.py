#!/usr/bin/python
# -*- coding: UTF-8 -*-
import re
import os
import sys
try:
    from bs4 import BeautifulSoup
except ImportError:
    raise SystemExit('\n[!]python3 html库——BeautifulSoup4导入错误;请执行 python3 -m pip install beautifulsoup4安装!')
import xlwt
import xlrd
from xlutils.copy import copy

##目录html文件读取
def path_file():
    path = sys.argv[1] + "\host\\"
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        host_path = []
        for file in filenames:
            tail = file.split('.')[-1]
            if tail == "html":  # print("files:" + os.path.join(dirpath, file))
                host_path1 = os.path.join(dirpath, file)
                host_path1 = host_path1.replace('\\\\', '\\').replace('/', '\\').replace('\n\r', '')
                host_path.append(host_path1)
        if host_path != []:
            return host_path

def search_data():
    host_path = path_file()
    ip_info = []
    ip_verison = []
    x_ip, x_version, x_port, x_port_version, x_vul_level, x_port_version_port_compare, x_vul_info_name, x_cve_num_row, x_vul_info_name_compare, x_vul_info_ms, x_vul_info_solution = [], [], [], [], [], [], [], [], [], [], []
    for w in host_path:
        file = open(w, 'r', encoding='utf-8')
        with file as wb_data:  # python打开本地网页文件
            Soup = BeautifulSoup(wb_data, 'lxml')  # 建立Soup对象，随后用select函数选取所需部分

            ##端口
            port_info = str(Soup.find_all("div", {"class": 'vul_summary'}))
            port = port_info.replace(' ', '').replace('\n', '').replace('<imgalign=', '\n\r<imgalign=')
            port = re.findall('"data-port="(.*)">', port)
            x_port.extend(port)

            for i in range(len(port)):
                ip = (Soup.find_all('td')[2].string)  ##IP地址
                ip_info.append(ip)
                x_ip = ip_info
                version = (Soup.find_all('td')[3].string)  ##系统版本
                ip_verison.append(version)
                x_version = ip_verison

            ##端口服务
            port_version = str(Soup.find_all("div", {"class": 'report_content'})[4])  ##端口服务
            if "5.1" not in port_version:
                port_version = "--"
            else:
                port_version = port_version.replace(' ', '').replace('\n', '').replace('<trclass','\n\r<trclass')
                port_version = re.findall('[tcp,udp]</td><td>(.*)</td><td>open', port_version)
                x_port_version.extend(port_version)

            ###端口服务_端口比
            port_version_port_compare = str(Soup.find_all("div", {"class": 'report_content'})[4])  ##端口服务
            if "5.1" in port_version_port_compare:
                port_version_port_compare = port_version_port_compare.replace(' ', '').replace('\n', '')
                port_version_port_compare = re.findall('远程端口信息(.*)open</td>',port_version_port_compare)
                port_version_port_compare = (str(port_version_port_compare)).replace('</td>','</td>\n\r')
                port_version_port_compare = re.findall('[odd,even]"><td>(.[\d]*)</td>', port_version_port_compare)
                #port_version_port_compare = list(set(port_version_port_compare))
                #port_version_port_compare = sorted(port_version_port_compare, key=lambda info: (int(info)))
                x_port_version_port_compare.extend(port_version_port_compare)

            ##漏洞简述-漏洞名称
            vul_info = str(Soup.find_all("table", {"id": 'vuln_list'}))
            vul_info_name = vul_info.replace(' ', '').replace('\n', '').replace('</span>', '</span>\n')
            vul_info_name = re.findall('"style="cursor:pointer">(.*)</span>', vul_info_name)
            x_vul_info_name.extend(vul_info_name)

            ##漏洞等级
            vul_info = vul_info.replace(' ', '').replace('\n', '').replace('</span>', '</span>\n')
            vul_level = re.findall('<spanclass="(.*)"onclick', vul_info)
            x_vul_level.extend(vul_level)

            # CVE编号
            cve_num = str(Soup.find_all("div", {"id": 'vul_detail'}))
            a = re.findall('详细描述',cve_num)
            cve_num = cve_num.replace(' ', '').replace('\n', '').replace('target', 'target\n\r')
            cve_num = cve_num.split('</td></tr></table></td></tr>')
            for i in range(len(a)):
                cve_num_row = re.findall('<ahref="http://cve.mitre.org/cgi-bin/cvename.cgi\?name=(.*)"target', cve_num[i])
                if cve_num_row == []:
                    x_cve_num_row.append([" "])
                else:
                    x_cve_num_row.append(cve_num_row)


            ##漏洞详情-漏洞名称
            vul_info_name_compare = str(Soup.find_all("table", {"class": 'report_table'})[4])
            vul_info_name_compare = vul_info_name_compare.replace(' ', '').replace('\n', '').replace('</span>',
                                                                                                     '</span>\n')
            vul_info_name_compare = re.findall('style="cursor:pointer">(.*)</span>', vul_info_name_compare)
            x_vul_info_name_compare.extend(vul_info_name_compare)

            ##漏洞描述##
            vul_info_ms = str(Soup.find_all("tr", {"class": 'odd'}))
            vul_info_ms = vul_info_ms.replace(' ', '').replace('\n', '').replace('</tr>', '\n\r')
            vul_info_ms = re.findall('详细描述</th><td>(.*)</td>', vul_info_ms)
            x_vul_info_ms.extend(vul_info_ms)

            ##修复方案##
            vul_info_solution = str(Soup.find_all("tr", {"class": 'even'}))
            vul_info_solution = vul_info_solution.replace(' ', '').replace('\n', '').replace('</tr>', '\n\r')
            vul_info_solution = re.findall('解决办法</th><td>(.*)</td>', vul_info_solution)
            x_vul_info_solution.extend(vul_info_solution)
            print("----------已读取[%s]！--------" %w)
        file.close()
    list={'x_ip': x_ip, 'x_version': x_version, 'x_port': x_port,'x_port_version': x_port_version, 'x_vul_level': x_vul_level, 'x_port_version_port_compare': x_port_version_port_compare, 'x_vul_info_name': x_vul_info_name, 'x_cve_num_row': x_cve_num_row, 'x_vul_info_name_compare': x_vul_info_name_compare, 'x_vul_info_ms': x_vul_info_ms, 'x_vul_info_solution': x_vul_info_solution
}
    return list

def input_data():
    list = search_data()
    x_ip, x_version, x_port, x_port_version, x_vul_level, x_port_version_port_compare, x_vul_info_name, x_cve_num_row, x_vul_info_name_compare, x_vul_info_ms, x_vul_info_solution = list['x_ip'], list['x_version'], list['x_port'], list['x_port_version'], list['x_vul_level'], list['x_port_version_port_compare'], list['x_vul_info_name'], list['x_cve_num_row'], list['x_vul_info_name_compare'], list['x_vul_info_ms'], list['x_vul_info_solution']
    workbook = xlwt.Workbook(encoding='utf-8')
    print()
    data_sheet = workbook.add_sheet('RSAS扫描结果',cell_overwrite_ok=True)
    row0 = [u'IP地址', u'操作系统', u'端口', u'服务', u'风险等级', u'CVE编号', u'漏洞名称', u'漏洞描述', u'解决方法']
    ##行模板
    for i in range(len(row0)):
        data_sheet.write(0, i, row0[i])
    #追加数据
    for i in range(len(x_port)):
       data_sheet.write(i+1, 0, x_ip[i])
    #系统版本写入
    for i in range(len(x_version)):
      ver = 'V6'
      if ver in x_version[i]:
          data_sheet.write(i+1, 1, "未检测到系统版本")
      else:
          data_sheet.write(i+1, 1, x_version[i])
   #端口写入
    for i in range(len(x_port)):
       data_sheet.write(i+1, 2, x_port[i])
   #服务写入##
    for i in range(len(x_port)):
      for s in range(len(x_port_version_port_compare)):
          if x_port[i] == x_port_version_port_compare[s]:
              data_sheet.write(i+1, 3, x_port_version[s])
   #风险等级写入
    for i in range(len(x_vul_level)):
       data_sheet.write(i+1, 4, x_vul_level[i])

   #漏洞名称写入##
    for i in range(len(x_vul_info_name)):
       data_sheet.write(i+1, 6, x_vul_info_name[i])
   #漏洞描述写入、解决方案写入、CVE编号写入
    for i in range(len(x_vul_info_name)):
      for s in range(len(x_vul_info_name_compare)):
          if x_vul_info_name_compare[s] == x_vul_info_name[i]:
              data_sheet.write(i+1, 5, x_cve_num_row[s])
              data_sheet.write(i+1, 7, x_vul_info_ms[s].replace('<br/><br/>','\r\n').replace('<br/>','\r\n'))
              data_sheet.write(i+1, 8, x_vul_info_solution[s].replace('<br/><br/>','\r\n').replace('<br/>','\r\n'))
          else:
              continue##
    workbook.save('./result.xls')  ###新表创建'''
    print("----------写入数据成功！--------")

def main():
	if len(sys.argv) < 2:
		sys.exit()
	else:
		input_data()
	pass

if __name__ == '__main__':
	main()
