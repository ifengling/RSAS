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


workbook = xlwt.Workbook(encoding='utf-8')
data_sheet = workbook.add_sheet('RSAS扫描结果')
row0 = [u'IP地址', u'操作系统', u'端口', u'服务', u'风险等级',u'CVE编号',u'漏洞名称', u'漏洞描述', u'解决方法']
##行模板
for i in range(len(row0)):
    data_sheet.write(0, i, row0[i])
workbook.save('.\result.xls')  ###新表创建'''

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
    for w in host_path:
        file = open(w, 'r', encoding='utf-8')
        with file as wb_data:  # python打开本地网页文件
            Soup = BeautifulSoup(wb_data, 'lxml')  # 建立Soup对象，随后用select函数选取所需部分
            ip = (Soup.find_all('td')[2].string)  ##IP地址
            version = (Soup.find_all('td')[3].string)  ##系统版本
            ##端口
            port_info = str(Soup.find_all("div", {"class": 'vul_summary'}))
            port = port_info.replace(' ', '').replace('\n', '').replace('<imgalign=', '\n\r<imgalign=')
            port = re.findall('"data-port="(.*)">', port)

            ##端口服务##
            port_version = str(Soup.find_all("tr", {"id": 'all_vul_not_support_exp'}))  ##端口服务
            port_version = port_version.replace(' ', '').replace('\n', '').replace('</span>', '</span>\n')
            port_version = re.findall('</td><td>(.*)</td><td><ul>', port_version)

            ##漏洞名称
            vul_info = str(Soup.find_all("table", {"id": 'vuln_list'}))
            vul_info_name = vul_info.replace(' ', '').replace('\n', '').replace('</span>', '</span>\n')
            vul_info_name = re.findall('"style="cursor:pointer">(.*)</span>', vul_info_name)

            ##漏洞等级
            vul_info = vul_info.replace(' ', '').replace('\n', '').replace('</span>', '</span>\n')
            vul_level = re.findall('<spanclass="(.*)"onclick', vul_info)

            ##漏洞名称
            vul_info_name_compare = str(Soup.find_all("table", {"class": 'report_table'})[4])
            vul_info_name_compare = vul_info_name_compare.replace(' ', '').replace('\n', '').replace('</span>',
                                                                                                     '</span>\n')
            vul_info_name_compare = re.findall('style="cursor:pointer">(.*)</span>', vul_info_name_compare)

            ##漏洞描述##
            vul_info_ms = str(Soup.find_all("tr", {"class": 'odd'}))
            vul_info_ms = vul_info_ms.replace(' ', '').replace('\n', '').replace('</tr>', '\n\r')
            vul_info_ms = re.findall('详细描述</th><td>(.*)</td>', vul_info_ms)

            ##修复方案##
            vul_info_solution = str(Soup.find_all("tr", {"class": 'even'}))
            vul_info_solution = vul_info_solution.replace(' ', '').replace('\n', '').replace('</tr>', '\n\r')
            vul_info_solution = re.findall('解决办法</th><td>(.*)</td>', vul_info_solution)

            ##获取xls
            workbook = xlrd.open_workbook(".\demo.xls")  # 打开工作簿
            sheets = workbook.sheet_names()  # 获取工作簿中的所有表格
            worksheet = workbook.sheet_by_name(sheets[0])  # 获取工作簿中所有表格中的的第一个表格
            rows_old = worksheet.nrows  # 获取表格中已存在的数据的行数
            new_workbook = copy(workbook)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_workbook.get_sheet(0)  # 获取转化后工作簿中的第一个表格

            ##追加数据
            for a in range(len(port)):
                new_worksheet.write(a + rows_old, 0, ip)
            ##系统版本写入
            for a in range(len(port)):
                ver = 'V6'
                if ver in version:
                    new_worksheet.write(a + rows_old, 1, "未检测到系统版本")
                else:
                    new_worksheet.write(a + rows_old, 1, version)
            ##端口写入
            for a in range(len(port)):
                new_worksheet.write(a + rows_old, 2, port[a])
            ##服务写入##
            # for a in range(len(vul_middle_info)):
            # new_worksheet.write(i + rows_old, 3, port_version[a])
            ##风险等级写入
            for a in range(len(vul_level)):
                new_worksheet.write(a + rows_old, 4, vul_level[a])
            ##CVE编号写入
            ##漏洞名称写入##
            for a in range(len(vul_info_name)):
                new_worksheet.write(a + rows_old, 6, vul_info_name[a])
            ##漏洞描述写入、解决方案写入
            for a in range(len(vul_info_name)):
                for s in range(len(vul_info_name_compare)):
                    if vul_info_name_compare[s] == vul_info_name[a]:
                        new_worksheet.write(a + rows_old, 7, vul_info_ms[s])
                        new_worksheet.write(a + rows_old, 8, vul_info_solution[s])
                    else:
                        continue
            new_workbook.save(".\result.xls")  # 保存工作簿
            print("----------追加【%s】写入数据成功！--------"%(w))
        file.close()

def main():
	if len(sys.argv) < 2:
		sys.exit()
	else:
		search_data()
	pass

if __name__ == '__main__':
	main()
