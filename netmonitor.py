#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
#   Author  :   eleven.i386
#   WebSite :   eleveni386.7axu.com
#   E-mail  :   eleven.i386@gmail.com
#   Date    :   13/03/08 12:02:28
#   Desc    :   流量监控悬浮窗程序
#   Use     :   需要sudo执行,或者以root用户执行.开启网卡混杂模式需要root
#

import gtk
import cairo
import gobject
import thread
import time
import netpcap

is_show = True
netread = netpcap.proc_traff()
gtk.gdk.threads_init()

def flush(widget):
    global netread
    while 1:
        netread = netpcap.read()
        widget.queue_draw()

def color_hex(color):
    gdk_color = gtk.gdk.color_parse(color)
    return (gdk_color.red / 65535.0, gdk_color.green / 65535.0, gdk_color.blue / 65535.0)

# UI配置 #################
swin_size = 220, 40
bwin_size = 300, 300
location = 1110, 26
transparency = 0.8
bg_pic = "./skin/bg.png"
fg = color_hex("#5E50E7")
font_size = 14.0
###########################

class BigWin(gtk.Window):
    """ 显示进程的流量的窗口 """
    def __init__(self):
        super(BigWin,self).__init__()
        # 取消边框
#        self.set_decorated(False)
        # 不在任务栏显示
        self.set_skip_taskbar_hint(True)
        self.connect("delete-event",self.on_hide)

        # 一个窗口 用来显示详细
        self.sw = gtk.ScrolledWindow()
        self.sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        self.sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        self.set_default_size(bwin_size[0],bwin_size[1])
        self.lstore = self.__create_model()
        # 保存上一次的信息
        self.treeview = gtk.TreeView(self.lstore)
        self.treeview.set_rules_hint(True)
        self.old_lstore = []
        self.Iters = {}
        self.model = self.treeview.get_model()

        self.sw.add(self.treeview)
        self.__add_columns(self.treeview)
        self.vbox = gtk.VBox()
        self.vbox.pack_start(self.sw)
        self.add(self.vbox)
        self.vbox.show()
        self.sw.show()

    def set_char(self,argc):
        self.__add_data(argc)

    def on_hide(self,event,data=None):
        global is_show
        self.hide()
        is_show = False
        return True

    def __add_data(self,lstore):

        def modify(Tuple):
            Tuple = list(Tuple)

            Tuple[3] = '0.00' + " " + Tuple[3].split()[-1]
            Tuple[4] = '0.00' + " " + Tuple[4].split()[-1]
            return tuple(Tuple)

        #self.lstore.clear()


        # 为了留住上一次出现的进程, 这次更新界面不会被刷新掉
        lstore_dict = dict((pid[1], pid) for pid in lstore )
        old_lstore_dict = dict((pid[1],pid) for pid in self.old_lstore ) if self.old_lstore else {}
        old_lstore_dict.update(lstore_dict)

        #print len(self.Iters), len(old_lstore_dict.values())

        if self.Iters:
            for item in old_lstore_dict.values():
                for index, elm in enumerate(item):
                    Iter = self.Iters.get(item[1], None)
                    if Iter:
                        self.lstore.set( Iter, index, elm )
                    else:
                        self.Iters[item[1]] = self.lstore.append([item[0], item[1], item[2], item[3], item[4], item[5], item[6]])

        else:
            for item in old_lstore_dict.values():
                self.Iters[item[1]] = self.lstore.append([item[0], item[1], item[2], item[3], item[4], item[5], item[6]])

        self.old_lstore = map(modify, old_lstore_dict.values())

        return self.lstore


    def __create_model(self):
        lstore = gtk.ListStore(str, int, str, str, str, str, str)
        return lstore

    def __add_columns(self, treeview):
        rendertext = gtk.CellRendererText()

        column = gtk.TreeViewColumn('Proto', rendertext, text=0)
        column.set_sort_column_id(0)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('PID', rendertext, text=1)
        column.set_sort_column_id(1)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('进程名称', rendertext, text=2)
        column.set_sort_column_id(2)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('下载速度', rendertext, text=3)
        column.set_sort_column_id(3)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('上传速度', rendertext, text=4)
        column.set_sort_column_id(4)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('下载流量', rendertext, text=5)
        column.set_sort_column_id(5)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('上传流量', rendertext, text=6)
        column.set_sort_column_id(6)
        treeview.append_column(column)

#        column = gtk.TreeViewColumn('进程状态', rendertext, text=7)
#        column.set_sort_column_id(7)
#        treeview.append_column(column)

class SmallWin(gtk.Window):
    """ 主窗口,悬浮窗 """
    def __init__(self):
        super(SmallWin,self).__init__()
        # 只有按下左键时拖动窗体
        self.drag = False
        self.mouse_x, self.mouse_y = 0,0
        # 窗口置顶
        self.set_keep_above(True)
        # 主窗体初始大小
        self.set_default_size(swin_size[0],swin_size[1])
        # 初始坐标
        self.x, self.y = location
        self.move(self.x, self.y)
        # 透明度
        self.set_opacity(transparency)
        # 主窗体响应鼠标点击事件
        self.add_events(gtk.gdk.BUTTON_PRESS_MASK|\
                        gtk.gdk.BUTTON_RELEASE_MASK|\
                        gtk.gdk.POINTER_MOTION_MASK|\
                        gtk.gdk.POINTER_MOTION_HINT_MASK)


        # 禁止调整窗口大小
#        self.set_resizable(False)
        # 不在任务栏显示
        self.set_skip_taskbar_hint(True)
        # 取消边框
        self.set_decorated(False)

        self.Bigw = BigWin()

        self.set_colormap(gtk.gdk.Screen().get_rgba_colormap())

        self.draw = gtk.DrawingArea()
        self.draw.connect("expose-event",self.on_expose)
        self.pixbuf = gtk.gdk.pixbuf_new_from_file(bg_pic)
        self.add(self.draw)

        self.connect("button-press-event",self.mouse_click)
        self.connect("button-release-event",self.mouse_release)
        self.connect("motion-notify-event",self.mouse_move)
        self.show_all()

        # 界面刷新线程
        thread.start_new_thread(flush,(self.draw,))

    def on_expose(self, widget, event):
        cr = widget.window.cairo_create()
        rect = widget.allocation
        cr.set_source_rgba(0, 0, 0, 0)
        cr.set_operator(cairo.OPERATOR_SOURCE)
        cr.paint()
        cr.set_source_pixbuf(self.pixbuf, rect.x, rect.y)
        cr.paint()
        cr.set_source_rgb(fg[0],fg[1],fg[2])
        cr.move_to(10.0,17.0)
        cr.set_font_size(font_size)
        cr.show_text(str(netread[1]))
        self.Bigw.set_char(netread[0])

    # 鼠标移动事件
    def mouse_move(self,widget,event,data=None):
        if self.drag:
            x,y = self.get_position()
            self.move((x+int(event.x)-int(self.mouse_x)),\
                        (y+int(event.y)-int(self.mouse_y)))

    # 点击释放事件
    def mouse_release(self,widget,event,data=None):
        if event.button == 1:self.drag = False

    # 点击按下事件
    def mouse_click(self,widget,event,data=None):
        global is_show
        if event.type == gtk.gdk._2BUTTON_PRESS:
            if is_show:
                self.Bigw.show_all()
                is_show = False
            else:
                self.Bigw.hide()
                is_show = True
            return

        if event.button == 3:
            self.destroy_quit(None, None)

        elif event.button == 1:
            self.drag = True
            self.mouse_x,self.mouse_y = event.x,event.y

    def destroy_quit(self, event, data=None):
        gtk.main_quit()

    def star(self):
        gtk.threads_enter()
        gtk.main()
        gtk.threads_leave()

if __name__ == "__main__":
    s = SmallWin()
    s.star()
