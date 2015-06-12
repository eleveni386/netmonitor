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
import socket
import fcntl
import struct
import psutil
from subprocess import Popen, PIPE

def local_IP(ifname):
    """本地ip"""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

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
    proc_names = {}
    proto_map = {
            (2, 1): 'tcp',
            (10, 1): 'tcp6',
            (2, 2): 'udp',
            (10, 2): 'udp6'
    }

    # get process name and pid
    for p in psutil.process_iter():
        try:
            proc_names[p.pid] = p.name()
        except psutil.Error:
            pass

    for c in psutil.net_connections():
        laddr = '%s:%s' % (c.laddr)
        raddr = ''

        if c.raddr:
            raddr = "%s:%s" % (c.raddr)

        if c.pid == None or raddr == '': continue
        info[laddr + " " + raddr] = proto_map.get((c.family, c.type)) + "/" + str(c.pid) + "/" + proc_names.get(c.pid)
        info[raddr + " " + laddr] = proto_map.get((c.family, c.type)) + "/" + str(c.pid) + "/" + proc_names.get(c.pid)
    return info

if __name__ == "__main__":
    import time
    while 1:
        for pid, value in get_pid().items():
            print pid, value
        print '\n'
        time.sleep(1)
