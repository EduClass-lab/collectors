#!/usr/bin/env python3

# Python 之间互相调用文件https://blog.csdn.net/winycg/article/details/78512300
from sub_convert import sub_convert
from list_update import update_url
from get_subs import subs

import json
import re
import os
import yaml
from urllib import request


# 分析当前项目依赖 https://blog.csdn.net/lovedingd/article/details/102522094


# 文件路径定义
Eterniy = './Eternity'

sub_list_json = './sub/sub_list.json'
sub_merge_path = './sub/'
sub_list_path = './sub/list/'

ipv4 = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
ipv6 = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'


def add_valid(line):
    if (line.__contains__("ssr://") or line.__contains__("ss://")
            or line.__contains__("trojan://") or line.__contains__("vmess://") or line.__contains__("vless://")):
        return line
    return ''


class sub_merge():
    def sub_merge(url_list):  # 将转换后的所有 Url 链接内容合并转换 YAML or Base64, ，并输出文件，输入订阅列表。

        os.makedirs(sub_list_path, exist_ok=True)
        content_list = []
        for t in os.walk(sub_list_path):
            for f in t[2]:
                f = t[0]+f
                os.remove(f)

        for (index, url_container) in enumerate(url_list):
            ids = url_list[index]['id']
            remarks = url_list[index]['remarks']
            if type(url_container['url']) == list:
                for each_url in url_container["url"]:
                    content = ''
                    print("gather server from " + each_url)
                    content += sub_convert.convert_remote(
                        each_url, 'url', 'http://127.0.0.1:25500')

                    if content == 'Url 解析错误':
                        content = sub_convert.main(each_url, 'url', 'url')
                        # Create file if it doesn't exist
                        if not os.path.exists(sub_list_path):
                            open(sub_list_path, 'w', encoding='utf-8').close()
                        if content != 'Url 解析错误':
                            if add_valid(content) != '':
                                content_list.append(content)
                            else:
                                print(f'this url failed{each_url}')
                            print(
                                f'Writing content of {remarks} to {ids:0>2d}.txt\n')
                        else:
                            print(
                                f'Writing error of {remarks} to {ids:0>2d}.txt\n')
                        file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                    'a+', encoding='utf-8')
                        file.write(content)
                        file.close()
                    elif content == 'Url 订阅内容无法解析':
                        file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                    'a+', encoding='utf-8')
                        file.write('Url Subscription could not be parsed')
                        file.close()
                        print(
                            f'Writing error of {remarks} to {ids:0>2d}.txt\n')
                    elif content != None:
                        if add_valid(content) != '':
                            content_list.append(content)
                        else:
                            print(f'this url failed{each_url}')
                        file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                    'a+', encoding='utf-8')
                        file.write(content)
                        file.close()
                        print(
                            f'Writing content of {remarks} to {ids:0>2d}.txt\n')
                    else:
                        file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                    'a+', encoding='utf-8')
                        file.write('Url Subscription could not be parsed')
