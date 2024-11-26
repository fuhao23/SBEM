"""
处理数据集
"""
import socket

import dpkt
import pandas as pd
from pandas import DataFrame

from FileUtils import saveDictToJson, readDictFromJson


class CICAPT2024:

    def extractLabelsToJson(self, labelfilepaths, savepath):
        """
        读取文件的标签，用于后文流量标记
        :return:
        """
        res = dict()
        totalsize = 0
        for csvpath in labelfilepaths:
            chunk_size = 10000  # 定义每个块的大小
            colNames = ["ts", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol Type",
                        "label",
                        "subLabel"]
            print(f"正在读取处理csv流量标记文件{csvpath}...")
            for chunk in pd.read_csv(csvpath, chunksize=chunk_size, dtype={69: str, 68: str}):
                # 在这里处理每个块
                chunkdata = chunk[colNames].values.tolist()
                for linedata in chunkdata:
                    totalsize += 1
                    lineInfo = {k: v for k, v in zip(colNames, linedata)}
                    srcip = lineInfo["Source IP"]
                    destip = lineInfo["Destination IP"]
                    srcport = lineInfo["Source Port"]
                    destport = lineInfo["Destination Port"]
                    if srcip > destip:
                        direction = True
                        keys = (srcip, srcport, destip, destport)
                    else:
                        direction = False
                        keys = (destip, destport, srcip, srcport)
                    keys = str(keys)
                    if keys not in res:
                        res[keys] = list()
                    res[keys].append({
                        "ts": lineInfo["ts"],
                        "protocol": lineInfo["Protocol Type"],
                        "label": lineInfo["label"],
                        "subLabel": lineInfo["subLabel"],
                        "direction": direction,
                    })
            print("分文件数量,", totalsize)
        print("正在保存结果")
        print("总数：", totalsize)
        saveDictToJson(res, savepath)

    def extractLabelsToCsv(self, labelfilepaths, savepath):
        """
        读取文件的标签，用于后文流量标记
        :return:
        """
        res = None
        for csvpath in labelfilepaths:
            chunk_size = 10000  # 定义每个块的大小
            colNames = ["ts", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol Type",
                        "label",
                        "subLabel"]
            print(f"正在读取处理csv流量标记文件{csvpath}...")
            for chunk in pd.read_csv(csvpath, chunksize=chunk_size, dtype={69: str, 68: str}):
                # 在这里处理每个块
                chunkdata = chunk[colNames]
                if res is None:
                    res = chunkdata
                else:
                    res = pd.concat([res, chunkdata], ignore_index=True)
            print("分文件数量,", res.size)
        print("正在保存结果")
        res.to_csv(savepath, index=False)

    def __determine_reader(self, pcapfilepath):
        """
        判断格式
        :return:
        """
        with open(pcapfilepath, 'rb') as f:
            magic = f.read(4)
            if magic == b'\xd4\xc3\xb2\xa1':
                return dpkt.pcap.Reader
            elif magic == b'\x4d\x3c\xb2\xa1':
                return dpkt.pcapng.Reader
            else:
                return dpkt.pcapng.Reader

    def extractPktAllInfo(self, pcappaths, savePath):
        """
        提取pcap能获取的所有信息
        由于IP层是通用的，这里不往下提取了
        :param pcappaths:
        :return:
        """
        res = dict()
        totalsize = 0
        for pcappath in pcappaths:
            Reader = self.__determine_reader(pcappath)
            with open(pcappath, 'rb') as f:
                pcap = Reader(f)
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        srcip = socket.inet_ntoa(ip.src)
                        dstip = socket.inet_ntoa(ip.dst)
                        protocol = ip.p
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            totalsize += 1
                            tcp = ip.data
                            srcport = tcp.sport
                            dstport = tcp.dport
                            payload = tcp.data
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            totalsize += 1
                            udp = ip.data
                            srcport = udp.sport
                            dstport = udp.dport
                            payload = udp.data
                        else:
                            continue
                        if srcip > dstip:
                            keys = (srcip, srcport, dstip, dstport)
                            direction = True
                        else:
                            keys = (dstip, dstport, srcip, srcport)
                            direction = False
                        keys = str(keys)
                        if keys not in res:
                            res[keys] = list()
                        res[keys].append({
                            "direction": direction,
                            "payload": payload.hex(),
                            "allpacket": buf.hex(),
                            "ts": ts,
                            "protocol": protocol,
                        })
            print("问及那：", totalsize)
        saveDictToJson(res, savePath)
        print("保存完毕！")
        print("总：", totalsize)

    def extractPktByTimestamp(self, pcappaths, savePath):
        """
        不按照tcp之类的提取了，误差大，直接按照IP提取
        :param savePath:
        :return:
        """
        res = dict()
        totalsize = 0
        for pcappath in pcappaths:
            Reader = self.__determine_reader(pcappath)
            with open(pcappath, 'rb') as f:
                pcap = Reader(f)
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        totalsize += 1
                        ip = eth.data
                        srcip = socket.inet_ntoa(ip.src)
                        dstip = socket.inet_ntoa(ip.dst)
                        protocol = ip.p
                        if srcip > dstip:
                            keys = (srcip, dstip)
                            direction = True
                        else:
                            keys = (dstip, srcip)
                            direction = False
                        keys = str(keys)
                        if keys not in res:
                            res[keys] = list()
                        res[keys].append({
                            "direction": direction,
                            "allpacket": buf.hex(),
                            "ts": ts,
                            "protocol": protocol,
                        })
            print("文件数量累计：", totalsize)
        saveDictToJson(res, savePath)
        print("保存完毕！")
        print("总：", totalsize)

    def extractPktByTimestampToCsv(self, pcappaths, savePath):
        """
        不按照tcp之类的提取了，误差大，直接按照IP提取
        :param savePath:
        :return:
        """

        res_data = list()
        for pcappath in pcappaths:
            Reader = self.__determine_reader(pcappath)
            with open(pcappath, 'rb') as f:
                pcap = Reader(f)
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        srcip = socket.inet_ntoa(ip.src)
                        dstip = socket.inet_ntoa(ip.dst)
                        protocol = ip.p
                        res_data.append([
                            ts,
                            srcip,
                            dstip,
                            protocol,
                            buf.hex(),
                        ])
            print("文件数量累计：", len(res_data))
        res = DataFrame(res_data, columns=["ts", "srcip", "dstip", "protocol", "allpacket"])
        res.to_csv(savePath, index=False)
        print("保存完毕！")

    def labelPktByLabels(self, pktpath, labelpath, savepath):
        """
        通过标签标记数据包
        :return:
        """
        res = list()
        labelfiledata = readDictFromJson(labelpath)
        pktfiledata = readDictFromJson(pktpath)
        for flowid, labeldatas in labelfiledata.items():
            if flowid in pktfiledata:
                walked_indexs = set()
                for labeldata in labeldatas:
                    for pkt_index, pktdata in enumerate(pktfiledata[flowid]):
                        if pkt_index in walked_indexs:
                            continue
                        label_ts = labeldata["ts"]
                        label_dir = labeldata["direction"]
                        label_protocol = labeldata["protocol"]
                        label_label = labeldata["label"]
                        label_sublabel = labeldata["subLabel"]
                        pkt_ts = pktdata["ts"]
                        pkt_dir = pktdata["direction"]
                        pkt_protocol = pktdata["protocol"]
                        pkt_payload = pktdata["payload"]
                        pkt_allpacket = pktdata["allpacket"]

                        if label_ts == pkt_ts and label_dir == pkt_dir and label_protocol == pkt_protocol:
                            walked_indexs.add(pkt_index)
                            res.append({
                                "payload": pkt_payload,
                                "allpacket": pkt_allpacket,
                                "label": label_label,
                                "sublabel": label_sublabel,
                            })

        saveDictToJson(res, savepath)

    def labelPkttsByLabels(self, pktpath, labelpath, savepath):
        """
        标记时间戳数据
        :param pktpath:
        :param labelpath:
        :param savepath:
        :return:
        """
        res = list()
        labelfiledata = readDictFromJson(labelpath)
        pktfiledata = readDictFromJson(pktpath)
        for flowid, labeldatas in labelfiledata.items():
            flowid = eval(flowid)
            flowid = tuple([flowid[0], flowid[2]])
            flowid = str(flowid)
            # print(flowid)
            if flowid in pktfiledata:
                walked_indexs = set()
                for labeldata in labeldatas:
                    for pkt_index, pktdata in enumerate(pktfiledata[flowid]):
                        if pkt_index in walked_indexs:
                            continue
                        label_ts = labeldata["ts"]
                        label_dir = labeldata["direction"]
                        # label_protocol = labeldata["protocol"]
                        label_label = labeldata["label"]
                        label_sublabel = labeldata["subLabel"]
                        pkt_ts = pktdata["ts"]
                        pkt_dir = pktdata["direction"]
                        # pkt_protocol = pktdata["protocol"]
                        pkt_allpacket = pktdata["allpacket"]

                        if label_ts == pkt_ts and label_dir == pkt_dir:
                            walked_indexs.add(pkt_index)
                            res.append({
                                "allpacket": pkt_allpacket,
                                "label": label_label,
                                "sublabel": label_sublabel,
                            })
        saveDictToJson(res, savepath)

    def labelPktcsvtsByLabels(self, pktpath, labelpath, savepath):
        """
        标记时间戳数据
        :param pktpath:
        :param labelpath:
        :param savepath:
        :return:
        """
        pkts = pd.read_csv(pktpath)
        print("数据包文件读取完毕")
        labels = pd.read_csv(labelpath)
        print("标签文件读取完毕")
        labels.rename(columns={
            "Source IP": "srcip",
            "Destination IP": "dstip",
            "Protocol Type": "protocol"
        }, inplace=True)
        res = pd.merge(pkts, labels, on=['ts'], how='inner')[
            ['allpacket', 'label', "subLabel"]]
        print("匹配完毕，正在保存......")
        res.to_csv(savepath, index=False)
        print("保存完毕，程序结束！")

    def analysis(self,datafilepath):
        """
        简单分析数据集文件
        :param datafilepath:
        :return:
        """
        data=pd.read_csv(datafilepath)
        print("数量：",data.size)
        print(data["subLabel"].unique())



if __name__ == '__main__':
    # 1、提取数据集中标签，用于打标记
    csvdatasetdirpaths = ['./data/cicaptdataset/raw/Phase1/phase1_NetworkData.csv',
                          "./data/cicaptdataset/raw/Phase2/phase2_NetworkData.csv"]
    pcapdatasetdirpaths = ['./data/cicaptdataset/raw/Phase1/1stPhase-timed-Merged.pcap',
                           "./data/cicaptdataset/raw/Phase2/2ndPhase-timed-MergedV2.pcap"]

    csvsavejsonpath = "./data/cicaptdataset/processed/labels.json"
    csvsavecsvpath = "./data/cicaptdataset/processed/labels.csv"

    allinfopcapsavepath = "./data/cicaptdataset/processed/Packet.json"
    tsinfopcapsavepath = "./data/cicaptdataset/processed/Packet_ts.json"
    tsinfopcapsavecsvpath = "./data/cicaptdataset/processed/Packet_ts.csv"

    pktlabeledsavepath = "./data/cicaptdataset/processed/pktlabeled.json"
    pkttsslabeledsavejsonpath = "./data/cicaptdataset/processed/pkttsslabeled.json"
    pkttsslabeledsavecsvpath = "./data/cicaptdataset/processed/pkttsslabeled.csv"
    datasetUtils = CICAPT2024()
    # datasetUtils.extractLabelsToCsv(csvdatasetdirpaths, csvsavecsvpath)

    # datasetUtils.extractPktAllInfo(pcapdatasetdirpaths, allinfopcapsavepath)
    # datasetUtils.extractPktByTimestamp(pcapdatasetdirpaths, tsinfopcapsavepath)
    # datasetUtils.extractPktByTimestampToCsv(pcapdatasetdirpaths, tsinfopcapsavecsvpath)

    # datasetUtils.labelPktByLabels(pcapsavepath, csvsavepath, pktlabeledsavepath)
    # datasetUtils.labelPkttsByLabels(tsinfopcapsavepath , csvsavepath, pkttsslabeledsavepath)
    # datasetUtils.labelPktcsvtsByLabels(tsinfopcapsavecsvpath, csvsavecsvpath, pkttsslabeledsavecsvpath)

    data=datasetUtils.analysis(pkttsslabeledsavecsvpath)
