import tkinter as tk
import tkinter.messagebox
import threading
from scapy.layers import inet
import math
from tkinter import ttk
import scapy
import math
from scapy.all import *

import numpy as np

import sniff1

addr = {}  # 存放目的地址
agreement = {}  # 存放协议数目
length = {}


class Length(object):
    def __init__(self, count, summ, aver, minl, maxl):
        self.count = count
        self.summ = summ
        self.aver = aver
        self.minl = 10000
        self.maxl = maxl


class pac(object):
    def __init__(self, count, byte):
        self.count = count
        self.byte = byte


# 创建tkinter主窗口
window = tk.Tk()
window.title('嗅探工具：')
window.geometry('800x600')

l = tk.Label(window, text='请您输入以太网卡ip：', width=50, height=3)
l.grid(row=0, column=3)
e = tk.Entry(window, show=None)
e.grid(row=1, column=3)
#var = tk.StringVar()  # 定义一个字符串变量
var = ""
No = 1
stop_flag = False
ipdata_list = []
stop_F = True
def strat():
    var = e.get()

    sn = sniff1.Sniffer()  # 创建Sniffer类
    sn.add(var)  # 加入被攻击对象

    def show(p):  # 处理数据包 根据数据包内容更新界面
        global No, stop_flag

        if stop_flag:
            raise Exception

        package = bytes(p[inet.IP])
        ip_data = {}  # 建立字典
        ip_data['version'] = package[0] >> 4
        ip_data['headLength'] = package[0] & 0x0f  # & 按位与操作
        ip_data['DSField'] = package[1]
        ip_data['totalLength'] = (package[2] << 8) + package[3]
        ip_data['identification'] = (package[4] << 8) + package[5]
        ip_data['flag'] = package[6] >> 5
        ip_data['moreFragment'] = ip_data['flag'] & 1
        ip_data['dontFragment'] = (ip_data['flag'] >> 1) & 1
        ip_data['fragmentOffset'] = ((package[6] & 0x1f) << 8) + package[7]
        ip_data['TTL'] = package[8]
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        ip_data['protocol'] = protocol_map[package[9]]
        ip_data['headerCheckSum'] = (package[10] << 8) + package[11]
        # 以IP地址形式存储
        ip_data['sourceAddress'] = "%d.%d.%d.%d" % (package[12], package[13], package[14], package[15])
        ip_data['destinationAddress'] = "%d.%d.%d.%d" % (package[16], package[17], package[18], package[19])
        ip_data['options'] = []
        # 根据headerLength求出options
        if ip_data['headLength'] > 5:  # 一般来说此处的值为0101，表示头长度为20字节、若超出则大于5（0101）
            temp = 5
            while temp < ip_data['headLength']:
                ip_data['options'].append(package[temp * 4] + 0)
                ip_data['options'].append(package[temp * 4] + 1)
                ip_data['options'].append(package[temp * 4] + 2)
                ip_data['options'].append(package[temp * 4] + 3)
                temp += 1
        # 根据totalLength求出data
        ip_data['data'] = []
        temp = ip_data['headLength'] * 4
        while temp < ip_data['totalLength']:
            ip_data['data'].append(package[temp])
            temp += 1
        if len(str(No))==1:
            result = 'No.'+' '+str(No)+'        '
        elif len(str(No))==2:
            result = 'No.' + ' ' + str(No) + '      '
        elif len(str(No))==3:
            result = 'No.' + ' ' + str(No) + '    '
        elif len(str(No))==4:
            result = 'No.' + ' ' + str(No) + '  '
        if len(ip_data['sourceAddress'])==15:
            result = result + 'Source' + ' ' + ip_data[
            'sourceAddress'] + '->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==14:
            result = result + 'Source' + '   ' + ip_data[
                'sourceAddress'] + '->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==13:
            result = result + 'Source' + '     ' + ip_data[
                'sourceAddress'] + '->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==12:
            result = result + 'Source' + '     ' + ip_data[
                'sourceAddress'] + ' -->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==11:
            result = result + 'Source' + '     ' + ip_data[
                'sourceAddress'] + ' --->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==10:
            result = result + 'Source' + '     ' + ip_data[
                'sourceAddress'] + '  --->' + 'Destination' + ' ' + ip_data['destinationAddress']
        elif len(ip_data['sourceAddress'])==9:
            result = result + 'Source' + '     ' + ip_data[
                'sourceAddress'] + '  ---->' + 'Destination' + ' ' + ip_data['destinationAddress']
        if len(ip_data['destinationAddress'])==15:
            result = result +'   ' + 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==14:
            result = result + '    '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==13:
            result = result + '      '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==12:
            result = result + '        '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==11:
            result = result + '         '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==10:
            result = result + '           '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        elif len(ip_data['destinationAddress'])==9:
            result = result + '             '+ 'protocol' + ' ' + ip_data['protocol'] + '\n'
        ipdata_list.append(ip_data)
        theLB.insert('end', result)  # 将每条输出插入到界面
        No = No + 1
        static(ip_data)
    threading.Thread(target=sn.start, args=[show]).start()  #双进程



b_1 = tk.Button(window, text='确定', width=12, height=2, command=strat).grid(row=2,column=3,pady=10)
theLB = tk.Listbox(window, width=100, height=15)


def static(ip_data):
    # 统计目的地址的数目

    temp = pac(0, 0)
    dip = ip_data['destinationAddress']
    if dip not in addr:
        addr[dip] = temp
        addr[dip].count = 1
        addr[dip].byte = ip_data['totalLength'] - ip_data['headLength']
    else:
        addr[dip].count = addr[dip].count + 1
        addr[dip].byte = addr[dip].byte + ip_data['totalLength'] - ip_data['headLength']

    dpro = ip_data['protocol']
    if dpro not in agreement:
        agreement[dpro] = 1
    else:
        agreement[dpro] = agreement[dpro] + 1

    temp = Length(0, 0, 0, 0, 0)
    slen = ip_data['totalLength']
    dlen = slen / 10
    dlen = math.log2(dlen)
    dlen = int(dlen)
    if dlen not in length:
        length[dlen] = temp
        length[dlen].count = 1
        length[dlen].summ = slen
        length[dlen].aver = round(slen, 2)
        length[dlen].min = slen
        length[dlen].max = slen
    else:
        length[dlen].count = length[dlen].count + 1
        length[dlen].summ += slen
        if slen > length[dlen].max:
            length[dlen].max = slen
        if slen < length[dlen].min:
            length[dlen].min = slen
        length[dlen].aver = length[dlen].summ / length[dlen].count
        length[dlen].aver = round(length[dlen].aver, 2)



def Callon(event):
    window1 = tk.Tk()
    window1.title('ip data')
    window1.geometry('680x400')
    line = theLB.index(tk.ANCHOR)
    data = ipdata_list[line]
    t = tk.Text(window1, width=100)
    for k, v in data.items():
        t.insert('end', '%s : %s\n' % (k, v))  # 将每条输出插入到界面
    t.pack(side='top')
    tk.Button(window1, text='确定', command=window1.destroy).pack()

theLB.bind('<Double-Button-1>',Callon)
theLB.grid(row=3,columnspan=8,column=0,rowspan=3,padx=50)

def stop():
    global stop_flag
    global stop_F
    window.title('已停止')
    stop_flag = True
    stop_F = False

def showstatic():
    window2 = tk.Tk()
    window2.title('统计数据')
    window2.geometry('600x400')
    # 创建滚动条
    scroll = tk.Scrollbar(window2, orient="vertical")
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    t_1 = tk.Text(window2, width=100, height=50, yscrollcommand=scroll.set)  # 将文本框关联到滚动条上，滚动条滑动，文本框跟随滑动
    scroll.config(command=t_1.yview)
    t_1.pack()
    # 将每条输出插入到界面并实时更新
    while stop_F:
        t_1.delete('1.0', 'end')
        t_1.insert('end', '协议统计：\n')
        for k, v in agreement.items():
            t_1.insert('end', '%s : %s\n' % (k, v))
        for key in addr:
            t_1.insert('end', '目的ip地址：'+key+'\n')
            t_1.insert('end', '发往该地址的包数目: '+str(addr[key].count)+'\n')
            t_1.insert('end', '发往该地址的总字节数: '+str(addr[key].byte)+'\n\n')



        window2.update_idletasks()
        window2.update()

def drawPic():
    window3 = tk.Tk()
    window3.title('统计图表')
    window3.geometry('600x300')
    tree = ttk.Treeview(window3)  # #创建表格对象
    tree["columns"] = ("Count", "total length", "aver", "min", "max")  # #定义列
    tree.pack()
    tree.column("Count", width=80)  # #设置列
    tree.column("total length", width=80)
    tree.column("aver", width=80)
    tree.column("min", width=80)
    tree.column("max", width=80)
    tree.heading("Count", text="Count")  # #设置显示的表头名
    tree.heading("total length", text="length")
    tree.heading("aver", text="average")
    tree.heading("min", text="min")
    tree.heading("max", text="max")
    for key in length:
        if key==1 or key==2 or key==3 or key==4 or key ==5 or key==6 or key==7 or key==8 or key==0:
                k = math.pow(2,key)*10
                length[key].count=0
                length[key].summ=0
                length[key].aver=0
                length[key].min=k
                length[key].max=0

    while stop_F:
        x = tree.get_children()
        for item in x:
            tree.delete(item)
        for key in length:
            if key == 0:
                tree.insert("", 0, text="0-19", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 1:
                tree.insert("", 1, text="20-39", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 2:
                tree.insert("", 2, text="40-79", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 3:
                tree.insert("", 3, text="80-159", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 4:
                tree.insert("", 4, text="160-319", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 5:
                tree.insert("", 5, text="320-639", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 6:
                tree.insert("", 6, text="640-1279", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 7:
                tree.insert("", 7, text="1280-2559", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))
            elif key == 8:
                tree.insert("", 8, text="2650-5119", values=(
                    length[key].count, length[key].summ, length[key].aver, length[key].min, length[key].max))

        tree.update()


def sigmoid(z):
	return 1 / (1 + np.exp(-z))

def predict(data):
    weight1 = np.array([[-6.34149440e-08, 3.11250139e+00, 3.96471144e+00,-1.99778064e+00,3.67359581e+00],
                        [-1.00000008e+00, -3.41899938e+00,  1.96495452e+00, -4.99947778e+00,2.22411776e+00],
                        [9.99999914e-01, -2.41925782e+00, 9.61929690e-01, -2.99947778e+00,-4.76308092e+00],
                        [3.99999966e+00, 4.08660444e+00, -4.03711621e+00, 1.21324123e-02,-1.87253784e+00],
                        [1.99999825e+00, 4.58100062e+00,-1.15372830e+00,-4.99947778e+00,2.72964996e-01]])
    weight2 = np.array([[ 3.4481516 ],
                        [ 1.62237529],
                        [ 0.72202415],
                        [ 1.95391195],
                        [-5.72600222]])
    value1 = np.array([[-4.99853279,-5.11188852,-0.95268736,-0.97690434,-4.9829566 ]])
    value2 = np.array([[2.55228248]])
    inputset = np.mat(data).astype(np.float64)
    output2 = sigmoid(np.dot(inputset, weight1) - value1)
    output3 = sigmoid(np.dot(output2, weight2) - value2)
    if output3 < 0.5:
        flag = 0
    else:
        flag = 1
    print(flag)
    return flag

def calEntropy(x):
    ans = 0
    sum = 0
    for key in x:
        sum = sum + x[key]
    for key in x:
        ans = ans + (x[key] / sum) * math.log(x[key] / sum)
    return -ans

def beep():
    tk.messagebox.showinfo("检测","warning!!!")

def sss():
    # 统计v2
    count = 0
    tk.messagebox.showinfo("检测","检测中")
    var = e.get()

    while True:
        countSyn = 0
        countSA = 0
        j = 0
        i = 0
        count = 0

        IP = {}
        Sport = {}
        Dport = {}
        Seq = {}

        s="ip src " + str(var) + " or ip dst " + str(var)
        packets = sniff(filter=s, count=100)
        for data in packets:
            if 'TCP' in data:
                i = i + 1
                isrc = data['IP'].src
                isport = data['TCP'].sport
                idport = data['TCP'].dport
                iseq = data['TCP'].seq
                if data['TCP'].flags == 'S':
                    countSyn = countSyn + 1
                if data['TCP'].flags == 'SA':
                    countSA = countSA + 1
                # 统计ip
                if isrc not in IP:
                    IP[isrc] = 1
                else:
                    IP[isrc] = IP[isrc] + 1
                # 统计sprot
                if isport not in Sport:
                    Sport[isport] = 1
                else:
                    Sport[isport] = Sport[isport] + 1
                # 统计dprot
                if idport not in Dport:
                    Dport[idport] = 1
                else:
                    Dport[idport] = Dport[idport] + 1
                # 统计seq
                if iseq not in Seq:
                    Seq[iseq] = 1
                else:
                    Seq[iseq] = Seq[iseq] + 1

        if (countSyn + countSA) == 0.0:
            v1 = 0.0
        else:
            v1 = countSyn / (countSyn + countSA)
        v2 = calEntropy(IP)
        v3 = calEntropy(Sport)
        v4 = calEntropy(Dport)
        v5 = calEntropy(Seq)

        result = [v1, v2, v3, v4, v5]
        flag = predict(result)
        if flag:
            count = count + 1
        else:
            count = 0
        if count >= 5:
            beep()

def drawCheck():
    threading.Thread(target=sss).start()  # 欺骗攻击对象



if __name__ == '__main__':
    b_2 = tk.Button(window, text='统计数据', width=12, height=2, command=showstatic).grid(row=6, column=1, pady=10, padx=50)
    b_3 = tk.Button(window, text='停止', width=12, height=2, command=stop).grid(row=6, column=4, padx=50)
    b_4 = tk.Button(window, text='统计图表', width=15, height=2, command=drawPic).grid(row=6, column=3, padx=50)

    b_5 = tk.Button(window, text='开始检测', width=15, height=2, command=drawCheck).grid(row=1, column=4, padx=50)
    window.mainloop()

