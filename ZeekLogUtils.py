"""
处理zeek的日志文件
"""
import json
from typing import NamedTuple

import networkx as nx
from matplotlib import pyplot as plt
from pyvis.network import Network

PacketInfo = NamedTuple('PacketInfo',
                        [('srcip', str), ('srcport', int), ('dstip', str), ('dstport', int), ('packet_direction', bool),
                         ('packet_len', int), ('packet_timestamp', int), ("packet_appinfo", str), ("other_info", str)])


class TrafficLoger:
    """
    流量数据处理相关
    """

    def __init__(self):
        self.packets = list()
        self.flows = dict()

    def readZeekLogRawData(self, filename):
        """
        读取原始的zeek日志文件
        :param filename:
        :return:
        """
        with open(filename, "r") as f:
            for line in f:
                data = json.loads(line)
                if "info" in data:
                    self.packets.append(
                        PacketInfo(srcip=data["srcip"], srcport=data["srcport"], dstip=data["dstip"],
                                   dstport=data["dstport"], packet_direction=data["is_orig"]
                                   , packet_timestamp=data["timestamp"], packet_len=data["applayerlength"],
                                   packet_appinfo=data["appinfo"], other_info=data["uid"]
                                   ))
                else:
                    self.packets.append(
                        PacketInfo(srcip=data["srcip"], srcport=data["srcport"], dstip=data["dstip"],
                                   dstport=data["dstport"], packet_direction=data["is_orig"]
                                   , packet_timestamp=data["timestamp"], packet_len=data["applayerlength"],
                                   other_info=data["uid"], packet_appinfo=""
                                   )
                    )

    def aggrateZeekPktToFlow(self):
        """
        将zeek的数据包信息聚合为数据流，同时排序
        :return:
        """
        # 首先按照uid聚合，从而降低排序时间
        # uid内的已经是排序了的，只需要排序uid的第一个就行
        resids = dict()
        for pi, packet in enumerate(self.packets):
            keys = tuple([packet.srcip, packet.srcport, packet.dstip, packet.dstport])
            if keys not in resids:
                resids[keys] = dict()
            if packet.other_info not in resids[keys]:
                resids[keys][packet.other_info] = list()
            resids[keys][packet.other_info].append([pi, packet.packet_timestamp])
        # 排序
        for flowid, flow in resids.items():
            if len(flow) == 1:
                self.flows[flowid] = [item[0] for item in list(flow.values())[0]]
            else:
                newflow = sorted(flow.items(), key=lambda tup: tup[1][0][1])
                self.flows[flowid] = list()
                for _, segflow in newflow:
                    self.flows[flowid].extend([item[0] for item in segflow])


if __name__ == '__main__':
    filepath = "data/test/ZeekLog/20240906.log"
    logger = TrafficLoger()
    logger.readZeekLogRawData(filepath)
    logger.aggrateZeekPktToFlow()

    windowssize = 32
    windowsData = [[item[0], item[2]] for item in logger.flows.keys()]
    print(windowsData)

    # ips=dict()
    # for flowid,_ in logger.flows.items():
    #     srcip=flowid[0]
    #     dstip=flowid[2]
    #     if srcip not in ips:
    #         ips[srcip] = 1
    #     else:
    #         ips[srcip] += 1
    #     if dstip not in ips:
    #         ips[dstip] = 1
    #     else:
    #         ips[dstip] += 1
    # print(ips)

    # pyvis绘制
    # net=Network(notebook=True)
    # net.toggle_physics(False)
    # net.from_nx(G)
    # net.show("test.html")
