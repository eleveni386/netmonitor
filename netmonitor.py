#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
#   Author  :   eleven.i386
#   E-mail  :   eleven.i386@gmail.com
#   Date    :   13/03/08 12:02:28
#   Desc    :   流量监控悬浮窗程序
#   Use     :   需要sudo执行,或者以root用户执行.开启网卡混杂模式需要root
#

import gtk
import cairo
import gobject
import netpcap

is_show = True

class other_win(gtk.Window):
    """ 显示进程的流量的窗口 """
    def __init__(self):
        super(other_win,self).__init__()
        # 取消边框
#        self.set_decorated(False)
        # 不在任务栏显示
        self.set_skip_taskbar_hint(True)
        self.connect("delete-event",self.on_hide)

        # 一个窗口 用来显示详细
        self.sw = gtk.ScrolledWindow()
        self.sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        self.sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        self.set_default_size(300,300)
        self.lstore = self.__create_model()
        treeview = gtk.TreeView(self.lstore)
        treeview.set_rules_hint(True)

        self.sw.add(treeview)
        self.__add_columns(treeview)
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
        self.lstore.clear()

        for item in lstore:
            self.lstore.append([item[0], item[1], item[2], item[3], item[4], item[5], "正在运行"])
        return self.lstore


    def __create_model(self):
        lstore = gtk.ListStore(int, str, str, str, str, str, str )
        return lstore

    def __add_columns(self, treeview):
        rendertext = gtk.CellRendererText()

        column = gtk.TreeViewColumn('PID', rendertext, text=0)
        column.set_sort_column_id(0)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('进程名称', rendertext, text=1)
        column.set_sort_column_id(1)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('下载速度', rendertext, text=2)
        column.set_sort_column_id(2)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('上传速度', rendertext, text=3)
        column.set_sort_column_id(3)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('下载流量', rendertext, text=4)
        column.set_sort_column_id(4)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('上传流量', rendertext, text=5)
        column.set_sort_column_id(5)
        treeview.append_column(column)

        column = gtk.TreeViewColumn('进程状态', rendertext, text=6)
        column.set_sort_column_id(6)
        treeview.append_column(column)

class main(gtk.Window):
    """ 主窗口,悬浮窗 """
    def __init__(self):
        super(main,self).__init__()
        # 只有按下左键时拖动窗体
        self.drag = False
        self.mouse_x, self.mouse_y = 0,0
        # 窗口置顶
        self.set_keep_above(True)
        # 主窗体初始大小
        self.set_default_size(220,24)
        # 初始坐标
        self.x, self.y = 1110, 26
        self.move(self.x, self.y)
        # 透明度
        self.set_opacity(0.8)
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

        self.ow = other_win()

        self.set_colormap(gtk.gdk.Screen().get_rgba_colormap())
        # cairo刷新区域显示total

        self.draw = gtk.DrawingArea()
        self.draw.connect("expose-event",self.on_expose)
        self.pixbuf = gtk.gdk.pixbuf_new_from_file("./skin/bg.png")
        self.add(self.draw)
        self.queue_draw

        self.connect("button-press-event",self.mouse_click)
        self.connect("button-release-event",self.mouse_release)
        self.connect("motion-notify-event",self.mouse_move)
        self.show_all()

    def on_expose(self, widget, event):
        cr = widget.window.cairo_create()
        rect = widget.allocation
        cr.set_source_rgba(0, 0, 0, 0)
        cr.set_operator(cairo.OPERATOR_SOURCE)
        cr.paint()
        cr.set_source_pixbuf(self.pixbuf, rect.x, rect.y)
        cr.paint()
        cr.set_source_rgb(0.0, 0.4588235294117647, 0.6588235294117647)
        cr.move_to(10.0,17.0)
        cr.set_font_size(15.0)
        ar = netpcap.read()
        cr.show_text(str(ar[1]))
        gobject.timeout_add(1000,self.queue_draw)
        self.ow.set_char(ar[0])

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
                self.ow.show_all()
                is_show = False
            else:
                self.ow.hide()
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
        gtk.main()

if __name__ == "__main__":
    s = main()
    s.star()
