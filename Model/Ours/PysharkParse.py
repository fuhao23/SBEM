import multiprocessing
import queue
import threading
import time
from datetime import datetime
from os import times

import pyshark

from FileUtils import saveDictToJson

livePktinfo = dict() # 临时保存数据包
flowsInfo = dict() # 保存流量的信息，按照目的IP后跟着流的形式保存
# 对模式进行选择，
# 0表示网络，1表示文件
mode=1

def cutFlow(flowdata, use_timestamp,timestamp,delta=60,):
    """
    将超时的数据流进行截断
    :return:
    """
    format = '%Y-%m-%d %H:%M:%S.%f'
    if use_timestamp:
        curtime=datetime.strptime(timestamp, format).timestamp()
    else:
        curtime = time.time()
    lastPkttime = flowdata[-1]["timestamp"]
    # 将时间字符串转换为datetime对象
    lastPkt_ts = datetime.strptime(lastPkttime, format).timestamp()
    if curtime - lastPkt_ts > delta:
        return True
    else:
        return False

def assemblePkts(packetinfo: dict, infos: dict, flows: dict):
    """
    将数据包信息进行组装
    :param packetinfo:
    :return:
    """
    """
    对数据报文进行组装
    """

    keys = (packetinfo["ipsrc"], packetinfo["portsrc"], packetinfo["ipdst"], packetinfo["portdst"])
    keys_rev = (packetinfo["ipdst"], packetinfo["portdst"], packetinfo["ipsrc"], packetinfo["portsrc"])

    if keys in infos:
        infos[keys].append({
            "timestamp": packetinfo["timestamp"],
            "applayerlen": packetinfo["applayerlen"],
            "payload": packetinfo["payload"],
            "direction": True
        })
    elif keys_rev in infos:
        infos[keys_rev].append({
            "timestamp": packetinfo["timestamp"],
            "applayerlen": packetinfo["applayerlen"],
            "payload": packetinfo["payload"],
            "direction": False
        })
    else:
        infos[keys] = [{
            "timestamp": packetinfo["timestamp"],
            "applayerlen": packetinfo["applayerlen"],
            "payload": packetinfo["payload"],
            "direction": True
        }]
    # 对流进行截断,并保存
    if mode==1:
        lastTs=packetinfo["timestamp"]
        useTs=True
    elif mode==0:
        lastTs=None
        useTs=False
    for flowid in list(infos.keys()):
        flowdata=infos[flowid]
        if cutFlow(flowdata,useTs,lastTs):
            srcip, srcport, dstip, dstport = flowid
            if int(srcport)>int(dstport):
                serverip=dstip
            else:
                serverip=srcip
            if serverip not in flows:
                flows[serverip] = dict()
            flows[serverip][str(flowid)] = flowdata
            del infos[flowid]

def analysis_packets(packet):
    """
    解析报文
    :param packet:
    :return:
    """
    pkt_info = dict()
    pkt_info['timestamp'] = str(packet.sniff_time)
    for layer in packet.layers:
        lyname = layer.layer_name
        for item in layer.field_names:
            pkt_info[lyname + "_" + item] = layer.get_field(item)
    try:
        timestamp = pkt_info['timestamp']
        srcmac = pkt_info['eth_src']
        dstmac = pkt_info['eth_dst']
        eth_type = pkt_info['eth_type']
        if eth_type != "0x0800" and eth_type != "0x86dd":
            return
        ipsrc = pkt_info['ip_src']
        ipdst = pkt_info['ip_dst']
        ipproto = pkt_info['ip_proto']
        portsrc = -1
        portdst = -1
        applayerlen = -1
        payload = ""
        if ipproto == '6':
            portsrc = pkt_info['tcp_srcport']
            portdst = pkt_info['tcp_dstport']
            applayerlen = pkt_info['tcp_len']
            if applayerlen != '0':
                payload = pkt_info['tcp_payload']
        elif ipproto == '17':
            portsrc = pkt_info['udp_dstport']
            portdst = pkt_info['udp_srcport']
            applayerlen = pkt_info['udp_length']
            if applayerlen != '0':
                payload = pkt_info['udp_payload']

        pkt_data = {
            "timestamp": timestamp,
            "srcmac": srcmac,
            "dstmac": dstmac,
            "ipsrc": ipsrc,
            "ipdst": ipdst,
            "ipproto": ipproto,
            "portsrc": portsrc,
            "portdst": portdst,
            "applayerlen": applayerlen,
            "payload": payload
        }
        assemblePkts(pkt_data, livePktinfo, flowsInfo, )
    except Exception as e:
        print(packet)
        print(e)

def consumer_packets(queue):
    """
    分析数据包
    :return:
    """
    # 这里读取从网卡或者文件的报文，之后进行解析
    while True:
        packet = queue.get()
        if packet is None:  # 用于停止消费者进程
            break
        analysis_packets(packet)
        queue.task_done()
    # 可能存在的剩余数据保存
    for flowid in list(livePktinfo.keys()):
        flowdata=livePktinfo[flowid]
        srcip, srcport, dstip, dstport = flowid
        if int(srcport)>int(dstport):
            serverip=dstip
        else:
            serverip=srcip
        if serverip not in flowsInfo:
            flowsInfo[serverip] = dict()
        flowsInfo[serverip][str(flowid)] = flowdata
    del livePktinfo
    # 这里已经解析完毕了，进行其他处理
    # 主进程主要抓包，这里主要是数据处理
    saveDictToJson(flowsInfo,"./data.json")




def captureLive(queue, interface='WLAN'):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=100000):
        queue.put(packet)

def capturePcap(pcapfilepath,queue):
    """
    解析pcap报文
    :param pcapfilepath:
    :return:
    """
    capture=pyshark.FileCapture(pcapfilepath)
    for packet in capture:
        queue.put(packet)


if __name__ == '__main__':
    # 创建一个队列
    packet_queue = multiprocessing.JoinableQueue(maxsize=10000)

    # 启动数据包捕获进程
    consumer_process = multiprocessing.Process(target=consumer_packets, args=(packet_queue,))
    consumer_process.start()

    # 启动生产者
    # captureLive(packet_queue)
    pcappath=r"C:\Users\gswsf\Files\codes\paper\SP2025\data\test\pcap\20240906.pcap"
    capturePcap(pcappath,packet_queue)

    # 停止消费者进程
    packet_queue.put(None)  # 发送停止信号
    consumer_process.join()
