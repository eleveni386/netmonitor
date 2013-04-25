#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
#   Author  :   eleven.i386
#   E-mail  :   eleven.i386@gmail.com
#   Date    :   13/04/09 22:19:55
#   Desc    :   流量采集模块
#


import pcap,dpkt,re
from netcore import *
import time
import thread

pc = pcap.pcap(get_Iface(),timeout_ms=1,promisc=False)
pc.setfilter("tcp")
total_info = {} # 每个进程总流量

def proc_traff(pid=None):
    """
        产生GUI/CLI使用数据,([(PID processname up down totalup totaldown status),(....)],"↑ 0.00 KB/S | ↓ 0.00 KB/S")
    """

    buf = {}
    pre = re.compile("^\-")
    proc_list = []
    total = ""
    p_name = set(get_pid().values())

    buf = {i:(0.00, 0.00) for i in p_name if i not in buf.keys()}

    for i in p_name:
        if i not in total_info.keys():total_info[i] = (0.00, 0.00)

    if pid != None:buf.update(pid)

    # 每个进程
    for i in buf:
        if not pre.match(i):

            total_info[i] = tuple(map(lambda x,y :x+y,total_info[i], buf[i]))
            proc_list.append((int(i.split('/')[0]),i.split('/')[1],conv(buf[i][0])+'/s', conv(buf[i][1])+'/s',conv(total_info[i][0]), conv(total_info[i][1])))

    # 总流量
    up = down = 0.00
    for i in buf:
           up += buf[i][1]
           down += buf[i][0]
    total = "↑ %s/S | ↓ %s/S"%(conv(up), conv(down))

    return (proc_list,total)

def traffic():
    ts = 1000
    net_info = {}# {"sourceip:sourceport destination:ip:destination:port":"data_byte"....}
    while 1:
        if ts < 1:break
        sip = dip = sport = dport = ""
        for t, pkt in pc.readpkts():
            if len(pkt) >1 :
                item = dpkt.ethernet.Ethernet(pkt)
                sip = "%d.%d.%d.%d"%(tuple(map(ord,list(item.data.src))))
                dip = "%d.%d.%d.%d"%(tuple(map(ord,list(item.data.dst))))
                if item.data.data.__class__.__name__ == 'TCP':
                    sport = item.data.data.sport
                    dport = item.data.data.dport
                    data_bytes = len(item.data.data.data)
                key = "%s:%s %s:%s"%(sip,sport,dip,dport)
                if net_info.has_key(key):net_info[key] = net_info[key] + data_bytes
                else: net_info[key] = data_bytes
        ts -= 1
        time.sleep(0.0001)

    return net_info

def handle(net):

    pid_info = {} # pid_info Format:{"PID/processname":data_bytes}
    process = get_pid()
    """
    将上传,下载流量合并成一组元组
    """
    for key in net:
        if process.has_key(key):
            localip = key.split()[0].split(':')[0] # 如果源地址是本机地址,则认为这段数据包是上传数据
#            print key,net[key]
            if localip == local_IP():
                Up = round(float(net[key])/1024, 2)
                Down = 0.00
                if pid_info.has_key(process[key]): pid_info[process[key]] = float(pid_info[process[key]][0]) + Down,\
                                                                            float(pid_info[process[key]][1]) + Up
                else: pid_info[process[key]] = Down, Up
            else:
                Up = 0.00
                Down = round(float(net[key])/1024, 2)
                if pid_info.has_key(process[key]): pid_info[process[key]] = float(pid_info[process[key]][0]) + Down,\
                                                                            float(pid_info[process[key]][1]) + Up
                else: pid_info[process[key]] = Down, Up

    return pid_info

def read():
    return proc_traff(handle(traffic()))
