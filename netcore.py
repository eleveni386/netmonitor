#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
#   Author  :   eleven.i386
#   WebSite :   eleveni386.7axu.com
#   E-mail  :   eleven.i386@gmail.com
#   Date    :   13/04/04 01:01:09
#   Desc    :   常用网络方法
#
import os,re,sys
from subprocess import Popen, PIPE

def local_IP():
    """本地ip"""
    return re.search('\d+\.\d+\.\d+\.\d+',Popen('/sbin/ifconfig', stdout=PIPE).stdout.read()).group(0)

def get_Iface():
    """默认通信网卡"""
    return  ''.join([ i.split()[-1] for i in os.popen('netstat -rn').readlines()[2:] if i.split()[0] == '0.0.0.0' ])

def conv(x):
    """数据字节单位转换"""
    if float(str(x).strip()) > 1024.0 and float(str(x).strip()) < 1048576.0 :return "%.2f"%round(x/1024.0,2) + " MB"
    elif float(str(x).strip()) > 1048576.0:return "%.2f"%round(x/1024.0/1024.0,2) + " GB"
    else:return "%.2f"%x + " KB"

def get_pid():
    """Format:
            info = {"192.168.1.244:37176 183.61.87.9:13034":"18277/chrome"}
    """
    info = {}
    net = os.popen("netstat -tnop").readlines()
    for i in net[2:]:
        info[i.split()[3] + " " + i.split()[4]] = i.split()[6]
        info[i.split()[4] + " " + i.split()[3]] = i.split()[6]
    return info

