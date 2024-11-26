import multiprocessing
import os
import socket
from cgi import print_environ
from datetime import datetime
from pprint import pprint
import dpkt

from FileUtils import saveDictToJson

"""-----------------pcap文件解析----------------------------"""
def packetProducer(pcappath,packet_queue):
    """
    从文件产生数据包
    :return:
    """
    with open(pcappath, 'rb') as f:

        pcap=dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            packet_queue.put((ts, buf))


"""-----------------数据包处理----------------------------"""
def changeByteToMac(data):
    """
    将原始的字节转化为字符串mac地址
    :return:
    """
    return ':'.join(f'{byte:02x}' for byte in data)

def packetConsumers(packet_queue,result_dict,lock):
    """
    收报文并处理
    :return:
    """
    while True:
        packet=packet_queue.get()
        # print("进程：",os.getpid(),"队列大小：",packet_queue.qsize())
        if packet is None:
            break
        process_packets(packet,result_dict,lock)

def process_packets(packet,result_dict,lock):
    """
    处理数据包
    :param packet:
    :return:
    """
    ts,buf=packet
    # 解析以太网
    try:
        pkt = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.NeedData:
        return
    # srcmac = changeByteToMac(pkt.src)
    # dstmac = changeByteToMac(pkt.dst)
    if isinstance(pkt.data, dpkt.ip.IP):
        ip = pkt.data
        srcip = socket.inet_ntoa(ip.src)
        dstip = socket.inet_ntoa(ip.dst)
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            srcport = tcp.sport
            dstport = tcp.dport
            payload = tcp.data
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            srcport = udp.sport
            dstport = udp.dport
            payload = udp.data
        else:
            return
        # 将数据合并到流数据
        flowKey=(srcip,srcport,dstip,dstport)
        flowKeyReverse=(dstip,dstport,srcip,srcport)
        result_dict["latestTs"] = ts
        with lock:
            if flowKey in result_dict:
                cur_data = result_dict[flowKey]
                cur_data.append({
                "ts":ts,
                "payloadlen":len(payload),
                    "direction":True
                })
                result_dict[flowKey] = cur_data
            elif flowKeyReverse in result_dict:
                cur_data = result_dict[flowKeyReverse]
                cur_data.append({
                    "ts":ts,
                    "payloadlen":len(payload),
                        "direction":False
                })
                result_dict[flowKeyReverse] = cur_data
            else:
                result_dict[flowKey]=[{
                    "ts": ts,
                    "payloadlen": len(payload),
                    "direction": True
                }]


"""-----------------数据流处理----------------------------"""
def changeTSstringToTimestamp(ts):
    """
    将时间字符串转换为时间戳
    :param ts:
    :return:
    """
    format = '%Y-%m-%d %H:%M:%S.%f'
    return datetime.strptime(ts, format).timestamp()

def flowProcess(result_dict,flow_dict,lock):
    """
    对数据流进行处理
    :param result_dict:
    :return:
    """
    delta=60
    print_enable=False
    oral_value=dict(flow_dict)
    while True:
        current_data = dict(result_dict)
        if current_data:
            latestTs=current_data["latestTs"]
            del current_data["latestTs"]
            if latestTs==-1:
                # 清空保存可能的数据
                for flowid in current_data.keys():
                    srcip, srcport, dstip, dstport = flowid
                    if srcport > dstport:
                        serverIp = dstip
                    else:
                        serverIp = srcip
                    curfdata=(flowid, current_data[flowid])
                    if serverIp not in flow_dict:
                        flow_dict[serverIp] = [curfdata]
                    else:
                        curdata = flow_dict[serverIp]
                        curdata.append(curfdata)
                        flow_dict[serverIp] = curdata
                    with lock:
                        del result_dict[flowid]
                break
        else:
            continue
        # 遍历划分
        for flowid in current_data.keys():
            # 对比时间戳
            lastestdata=current_data[flowid][-1]
            flowlastestTs=lastestdata['ts']
            if latestTs-flowlastestTs>delta:
                srcip,srcport,dstip,dstport=flowid
                if srcport>dstport:
                    serverIp=dstip
                else:
                    serverIp=srcip
                flow_data=(flowid,current_data[flowid])
                if serverIp not in flow_dict:
                    flow_dict[serverIp]=[flow_data]
                else:
                    curdata=flow_dict[serverIp]
                    curdata.append(flow_data)
                    flow_dict[serverIp]=curdata
                with lock:
                    del result_dict[flowid]

        if dict(flow_dict)!=oral_value and print_enable:
            print("----------------------")
            for serverip,flowdata in flow_dict.items():
                print("-------------")
                print(serverip)
                for flowid,pkts in flowdata:
                    print(flowid,pkts[-1]["ts"])
                    print([item["payloadlen"] for item in pkts])
            oral_value=dict(flow_dict)


"""-----------------流聚合处理----------------------------"""

def flowIOCProcess(flow_dict,ioc_dict,lock):
    """
    通过数据流计算其IOC数据
    :param flow_dict:
    :return:
    """
    for serverIp, flowdata in flow_dict.items():
        pass

if __name__ == '__main__':
    packet_queue = multiprocessing.Queue()
    # 创建一个共享字典
    manager = multiprocessing.Manager()
    pkt_dict = manager.dict() # 用来保存数据包实时信息
    flow_dict=manager.dict() # 保存流信息
    ioc_dict = manager.dict()  # 保存聚合的IP的情报信息
    # 锁
    lock = multiprocessing.Lock()

    pcappath=r"C:\Users\gswsf\Files\codes\paper\SP2025\data\cicaptdataset\raw\Phase2\2ndPhase-timed-MergedV2.pcap"
    # pcappath = r"C:\Users\gswsf\Files\codes\paper\SP2025\data\test\pcap\20241008.pcap"
    # 数据报文处理进程

    num_packetProcess_processes=2
    processes=list()
    for _ in range(num_packetProcess_processes):
        p=multiprocessing.Process(target=packetConsumers,args=(packet_queue,pkt_dict,lock))
        p.start()
        processes.append(p)

    # 启动数据生产进程
    pkt_producer_process = multiprocessing.Process(target=packetProducer, args=(pcappath, packet_queue))
    pkt_producer_process.start()
    # 启动流聚合进程
    flow_producer_process = multiprocessing.Process(target=flowProcess, args=(pkt_dict,flow_dict,lock))
    flow_producer_process.start()

    # 等待数据生产完成
    # 这个结束了再结束其他的
    pkt_producer_process.join()
    print("文件处理完毕")
    # 等待流进程完成
    pkt_dict["latestTs"]=-1
    flow_producer_process.join()
    print("数据包处理完毕")
    # 结束数据处理进程
    for _ in range(num_packetProcess_processes):
        packet_queue.put(None)
    for p in processes:
        p.join()
    print("正在保存数据")
    saveDictToJson(dict(flow_dict),"./flowdata.json")



