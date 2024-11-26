"""
静态提取数据，加快速度
"""
import math
import socket
from collections import Counter

import dpkt
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from numpy import mean, std
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from FileUtils import saveDictToJson, readDictFromJson


def readPcapAndSavePkt(pcappaths, savePath):
    """
    读取pcap数据，之后保存为数据包格式数据
    :return:
    """
    res = list()
    for pcappath in pcappaths:
        with open(pcappath, 'rb') as f:
            pcap = dpkt.pcapng.Reader(f)
            for ts, buf in pcap:
                # 解析以太网
                try:
                    pkt = dpkt.ethernet.Ethernet(buf)
                except dpkt.dpkt.NeedData:
                    continue
                # srcmac = changeByteToMac(pkt.src)
                # dstmac = changeByteToMac(pkt.dst)
                if isinstance(pkt.data, dpkt.ip.IP):
                    ip = pkt.data
                    srcip = socket.inet_ntoa(ip.src)
                    dstip = socket.inet_ntoa(ip.dst)
                    protocol = None
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        srcport = tcp.sport
                        dstport = tcp.dport
                        payload = tcp.data
                        protocol = "tcp"
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        srcport = udp.sport
                        dstport = udp.dport
                        payload = udp.data
                        protocol = "udp"
                    else:
                        continue
                    # 将数据合并到流数据
                    res.append([
                        ts,
                        srcip,
                        dstip,
                        srcport,
                        dstport,
                        len(payload),
                        protocol,
                    ])
    columns = ["ts", "srcip", "dstip", "srcport", "dstport", "payloadlen", "protocol"]
    df = pd.DataFrame(res, columns=columns)
    df.to_csv(savePath, index=False, encoding='utf-8')


def labelPkt(labelpaths, pktpath, respath):
    """
    将数据包打标签
    :return:
    """
    # 读数据
    pktdata = pd.read_csv(pktpath)
    print("流量数据读取完毕！")
    lablesTotal = None
    for labelpath in labelpaths:
        print("正在处理：", labelpath)
        labeldata = pd.read_csv(labelpath)
        if lablesTotal is None:
            lablesTotal = labeldata
        else:
            lablesTotal = pd.concat([lablesTotal, labeldata], ignore_index=True)
    print("标签拼接完毕，开始计算列表")
    res_df = pd.merge(pktdata, lablesTotal, on='ts', how='left')[
        ['ts', 'srcip', 'dstip', 'srcport', 'dstport', 'payloadlen', 'protocol', 'label', 'subLabel', 'subLabelCat']]
    print("保存结果")
    res_df.to_csv(respath, index=False, encoding='utf-8')


def aggrToFlow(datasetpath, flowpath):
    """
    将报文汇集成流
    :return:
    """
    pktdata = pd.read_csv(datasetpath).values.tolist()
    # 对数据包进行聚合
    flows = dict()
    for (ts, srcip, dstip, srcport, dstport, payloadlen, protocol, label, subLabel, subLabelCat) in pktdata:
        flowid = str((srcip, srcport, dstip, dstport))
        flowid_rev = str((dstip, dstport, srcip, srcport))
        if flowid in flows:
            flows[flowid].append([ts, payloadlen, protocol, label, subLabel, subLabelCat, True])
        elif flowid_rev in flows:
            flows[flowid_rev].append([ts, payloadlen, protocol, label, subLabel, subLabelCat, False])
        else:
            flows[flowid] = [[ts, payloadlen, protocol, label, subLabel, subLabelCat, True]]
    saveDictToJson(flows, flowpath)
    print("保存完毕")


def aggrToServerIp(flowpath, savepath):
    """
    按照服务器IP聚合
    :return:
    """
    data = readDictFromJson(flowpath)
    res = dict()
    for flowid, flowdata in data.items():
        srcip, srcport, dstip, dstport = eval(flowid)
        # if srcport > dstport:
        #     serverIp = dstip
        # else:
        #     serverIp = srcip
        serverIp = dstip
        if serverIp not in res:
            res[serverIp] = list()
        res[serverIp].append((flowid, flowdata))
    saveDictToJson(res, savepath)


def serverIpInfoScan():
    """
    对服务器IP数据的分布查看
    :return:
    """
    # 打印流数据信息
    data = readDictFromJson(r"../../data/cicaptdataset/processed/serverIpFlows.json")
    for serverip, serverdata in data.items():
        print("--------------")
        print("服务器IP：【", serverip, "】")
        for flowid, flowdata in serverdata:
            for item in flowdata:
                print(flowid)
                print([item[1] for item in flowdata], set([item[4] for item in flowdata]))

    # 查看流大小分布
    flowlens = list()
    data = readDictFromJson(r"../../data/cicaptdataset/processed/serverIpFlows.json")
    for serverIp, serverData in data.items():
        for flowid, flowdata in serverData:
            flowlens.append(len(flowdata))
    # 画图展示
    # 计算每个长度值的出现次数
    length_counts = Counter(flowlens)

    # 将长度值排序并获取对应的计数
    sorted_lengths = sorted(length_counts.keys())
    counts = [length_counts[length] for length in sorted_lengths]

    # 计算累计数量
    cumulative_counts = [sum(counts[:i + 1]) for i in range(len(counts))]

    # 计算累计百分比
    total_count = sum(counts)
    cumulative_percentages = [100 * cumulative_count / total_count for cumulative_count in cumulative_counts]

    # 绘制折线图
    plt.plot(sorted_lengths, cumulative_percentages, marker='o')  # marker='o'表示用圆圈标记每个数据点
    plt.title('Cumulative Percentage Distribution of Lengths')
    plt.xscale('log')  # 设置x轴为对数尺度
    plt.xlabel('Length')
    plt.ylabel('Cumulative Percentage')
    plt.grid(True)  # 添加网格线
    plt.show()


#-----------判定相似度---------------
def splitFlowByDir(flows, direction):
    """
    通过方向将一个流划分成小块
    每个小块都是同一个方向的
    :param flows:
    :param direction:
    :return:
    """
    assert len(flows) == len(direction)
    res = list()
    curdir = direction[0]
    orallist = list()
    orallist.append(flows[0])
    for d_i, pktdir in enumerate(direction):
        if d_i == 0:
            continue
        if curdir == pktdir:
            orallist.append(flows[d_i])
        else:
            res.append(orallist)
            orallist = list()
            orallist.append(flows[d_i])
            curdir = pktdir
    res.append(orallist)
    return res


def judgeListSame(data: list):
    """
    主要计算字符串相同字符
    :param flows:
    :return:
    """

    # 判断是不是二维列表
    if isinstance(data[0], list):
        data_1D = [subitem for item in data for subitem in item]
        data_p = data_1D
    else:
        data_p = data
    if len(set(data_p)) == 1:
        return data_p[0], len(data_p)
    else:
        return -1, -1


def judgeSegSame(seg1, seg2):
    """
    判断两个序列片段是不是相似的
    这个主要是为了流片段判断
    :param seg1:
    :param seg2:
    :return:
    """
    # 完全相同的肯定相似
    if seg1 == seg2:
        return True
    # 如果元素相同，也认为相似
    # 放款宽件，只要有2个元素以内不同的长的可以接受也
    if set(seg1) == set(seg2) or (
            len(set(seg2).symmetric_difference(set(seg1))) <= 2 and abs(len(seg1) - len(seg2)) < 2):
        return True
    # 如果和相同，也认为相似
    if sum(seg1) == sum(seg2):
        return True
    # 否则不相似
    return False


# def judgeSegsSame(segList1,segList2):
#     """
#     判断两个seg的列表是不是相似
#     就是上面那个不带s的函数，输入变成列表了
#     segList1作为当前被匹配的，2是要匹配的
#     -------
#     还是采用动态匹配的方法，如果能匹配就匹配，不能匹配往后看（先尝试静态匹配）
#     :param segList1:
#     :param segList2:
#     :return:
#     """
#     minlen=min(len(segList1),len(segList2))
#     maxlen=max(len(segList1),len(segList2))
#     totalsame=0
#     totaldif=0
#     for l_i in range(minlen):
#         seg1=segList1[l_i]
#         seg2=segList2[l_i]
#         seg_is_sim=judgeSegSame(seg1,seg2) # 判断两个片段是不是类似
#         if seg_is_sim:
#             totalsame+=1
#         else:
#             totaldif+=2
#     totaldif+=maxlen-minlen
#     return totalsame/(totalsame+totaldif)

def judgeSingleDirSegsSame(segList1, segList2):
    """
    判断一个方向的流的相似性
    :param segList1:
    :param segList2:
    :return:
    """
    if (len(segList1) == 0 and len(segList2) != 0) or (len(segList1) != 0 and len(segList2) == 0):
        return 0
    if len(segList1) == 0 and len(segList2) == 0:
        return -1
    totalsame = 0
    seg1_startindex = -1
    for l1_i in range(len(segList1)):
        if l1_i < seg1_startindex:
            continue
        seg1 = segList1[l1_i]
        seg2_startindex = -1
        score = 1
        for l2_i in range(len(segList2)):
            if l2_i < seg2_startindex:
                continue
            seg2 = segList2[l2_i]
            seg_is_sim = judgeSegSame(seg1, seg2)  # 判断两个片段是不是类似
            if not seg_is_sim:
                if l2_i < len(segList2) - 1 and sum(seg1) > sum(seg2) and set(seg2).issubset(set(seg1)):  # 判断和后一个
                    seg_is_sim = judgeSegSame(seg1, segList2[l2_i] + segList2[l2_i + 1])
                    if not seg_is_sim:
                        seg2_startindex = l2_i + 1
                    else:
                        totalsame += score
                        seg2_startindex = l2_i + 2
                elif l1_i < len(segList1) - 1 and sum(seg2) > sum(seg1) and set(seg1).issubset(set(seg2)):  # 判断和后一个
                    seg_is_sim = judgeSegSame(segList1[l1_i] + segList1[l1_i + 1], seg2)
                    if not seg_is_sim:
                        seg2_startindex = l2_i + 1
                    else:
                        totalsame += 2 * score
                        seg1_startindex = l1_i + 2
                        seg2_startindex = l2_i + 1
            else:
                totalsame += score
            break
    return totalsame / (1 * len(segList1))


def judgeSegsSame(segList1, segList2):
    """
    判断两个seg的列表是不是相似
    就是上面那个不带s的函数，输入变成列表了
    segList1作为当前被匹配的，2是要匹配的
    -------
    还是采用动态匹配的方法，如果能匹配就匹配，不能匹配往后看（先尝试静态匹配）
    :param segList1:
    :param segList2:
    :return:
    """
    trueSegs1 = [item for i_i, item in enumerate(segList1) if i_i % 2 == 0]
    falseSegs1 = [item for i_i, item in enumerate(segList1) if i_i % 2 == 1]
    trueSegs2 = [item for i_i, item in enumerate(segList2) if i_i % 2 == 0]
    falseSegs2 = [item for i_i, item in enumerate(segList2) if i_i % 2 == 1]
    trueScore = judgeSingleDirSegsSame(trueSegs1, trueSegs2)
    falseScore = judgeSingleDirSegsSame(falseSegs1, falseSegs2)
    if trueScore == -1:
        return falseScore
    elif falseScore == -1:
        return trueScore
    return (trueScore + falseScore) / 2


def staticList(data):
    """
    统计列表数据出现次数
    :param data:
    :return:
    """
    return dict(Counter(data))


def judgeTowListSame(centerList, pairList):
    """
    判断两个列表相似度
    :return:
    """
    total = 0
    empty = False
    for dir in [True, False]:
        c_data = centerList[dir]
        p_data = pairList[dir]
        if (len(c_data) == 0 and len(p_data) != 0) or (len(c_data) != 0 and len(p_data) == 0):
            continue
        if len(c_data) == 0 and len(p_data) == 0:
            empty = True
            continue

        c_dict = staticList(c_data)
        p_dict = staticList(p_data)
        same_num = 0
        diff_num = 0
        for k, v in c_dict.items():
            if k in p_dict:
                same_num += min(v, p_dict[k])
                diff_num += abs(v - p_dict[k])
            else:
                diff_num += v
        for k, v in p_dict.items():
            if k not in c_dict:
                diff_num += v
        total += same_num / (diff_num + same_num)
    if empty:
        return total
    else:
        return total / 2


def judgeSetSame(centerList, pairList):
    """
    判断两个列表的元素相似度
    :param centerList:
    :param pairList:
    :return:
    """
    total = 0
    empty = False
    for dir in [True, False]:
        c_data = centerList[dir]
        p_data = pairList[dir]
        if len(c_data) == 0 and len(p_data) == 0:
            empty = True
            continue
        if (len(c_data) == 0 and len(p_data) != 0) or (len(c_data) != 0 and len(p_data) == 0):
            continue
        d_c = set(c_data)
        p_c = set(p_data)
        intersection = len(d_c.intersection(p_c))
        union = len(d_c.union(p_c))
        total += intersection / union
    if empty:
        return total
    else:
        return total / 2


def judgePktsSame(segList1, segList2):
    """
    计算指定方向的数据包类似情况
    :param segList1:
    :param segList2:
    :return:
    """
    PktList1 = {
        True: list(),
        False: list()
    }
    PktList2 = {
        True: list(),
        False: list()
    }
    dir = True
    for item in segList1:
        PktList1[dir].extend(item)
        dir = not dir
    dir = True
    for item in segList2:
        PktList2[dir].extend(item)
        dir = not dir
    # 判断整体上相似
    simTotal = judgeTowListSame(PktList1, PktList2)
    simSet = judgeSetSame(PktList1, PktList2)
    # print("集合：",simSet)
    return max(simSet, simTotal)


def judgeFlowSame(segList1, segList2):
    """
    判断两个流是不是匹配
    """
    simSeg = judgeSegsSame(segList1[0], segList2[0])
    simPkt = judgePktsSame(segList1[0], segList2[0])
    # print("-------------------------")
    # print("List1:",len(segList1[0]),segList1[0][:20])
    # print("labels1:", set(segList1[1]))
    # print("List2:",len(segList2[0]),segList2[0][:20])
    # print("labels2:",set(segList2[1]))
    # print("评价分数：",simSeg,simPkt,max(simSeg,simPkt))
    return max(simSeg, simPkt)


def judgeSimBetweenSegsList(curSegsList, pairSegsList):
    """
    判断两个list之间的相似度
    :param curList:
    :param pairList:
    :return:
    """
    # 判断是不是全是相同元素
    c_same = judgeListSame(curSegsList[0])
    p_same = judgeListSame(pairSegsList[0])
    if c_same[0] == p_same[0] and c_same[0] != -1:
        return 1  # 相同的直接相似
    # 判断是不是分割的子元素相似性
    score = judgeFlowSame(curSegsList, pairSegsList)
    return score


class ServiceGroup:
    """"
    对流量进行分组划分
    """

    def __init__(self):
        self.group = list()

    def _new_subgroup(self, data: list):
        """
        添加新的自组
        :return:
        """
        # 一个子组中，包含的内容
        # 1、这个当前的片段，以及这个片段和其他列表相似度的计算
        # 2、中心点的中心
        self.group.append({"data": [[data, 1]], "center": 0})

    def _insert_subgroup(self, data: list, group_index):
        """
        将数据插入到列表中
        涉及的是添加节点并重新计算中心节点
        :param group_index:
        :param new_sim:
        :param data:
        :return:
        """
        sub_group = self.group[group_index]  # 选择的子组
        sub_group_len = len(sub_group["data"])  # 子组的元素数量
        # 计算这个点和组里面其他节点相似度
        new_node_score = 1
        score_list = list()
        for n_i, node in enumerate(sub_group["data"]):
            totalScore = node[1] * sub_group_len  # 总的相似度
            f_score = judgeSimBetweenSegsList(node[0], data)
            self.group[group_index]["data"][n_i][1] = (totalScore + f_score) / (sub_group_len + 1)
            new_node_score += f_score
            score_list.append(self.group[group_index]["data"][n_i][1])
        new_node_score /= (sub_group_len + 1)
        score_list.append(new_node_score)
        # 添加节点数据
        self.group[group_index]["data"].append([data, new_node_score])
        # 选择新的中心节点
        max_value = max(score_list)
        # 使用index方法找到最大值的下标
        max_index = score_list.index(max_value)
        self.group[group_index]["center"] = max_index

    def add(self, data):
        """
        向组添加数据
        :return:
        """
        # 如果组是空的，直接添加
        if not self.group:
            self._new_subgroup(data)
        else:
            # 不是空的，计算和各组中心点的距离
            # 各组选择自己的中心点，这个中心点是和其他各个点的最相似的点
            allscore = list()
            isFastPair = False
            for subg_i, subgroup in enumerate(self.group):
                center_note = subgroup["data"][subgroup["center"]][0]
                # 流长度超过一定范围就不比较了，没意义
                if abs(len(center_note[0]) - len(data[0])) > 100:
                    continue
                sim = judgeSimBetweenSegsList(center_note, data)  # 计算和中心点相似度
                if sim == 1:
                    # 已经是最大的，就跳过，不比较了
                    self._insert_subgroup(data, subg_i)
                    isFastPair = True
                    break
                allscore.append(sim)
            # 如何快速匹配了，直接跳过
            if isFastPair:
                return

            # 选择最大的相似度点
            print("所有分数：", allscore)
            if allscore:
                max_value = max(allscore)
                if max_value > 0.85:
                    # 相似度大，则插入
                    max_index = allscore.index(max_value)
                    self._insert_subgroup(data, max_index)
                else:
                    self._new_subgroup(data)
            else:
                self._new_subgroup(data)

    def getGroup(self):
        return self.group


def calFingerByServerIp(serverIpPath, savepath):
    """
    通过服务器IP计算指纹
    :return:
    """
    # 按照服务器IP进行服务器指纹提取
    print("正在读取IP流数据读")
    data = readDictFromJson(serverIpPath)
    # data={"172.16.65.128":data["172.16.65.128"]}
    print("IP流数据读取完毕")
    res = dict()
    for serverip, serverdata in data.items():
        print("正在处理：", serverip)
        # 保存划分后服务的类别结果
        groups = ServiceGroup()
        for s_i, (flowid, flowdata) in enumerate(serverdata):
            print(f"进度：{s_i / len(serverdata)}")
            flowpktlens = tuple([item[1] for item in flowdata])  # 当前流的大小
            flowpktdirs = tuple([item[-1] for item in flowdata])  # 当前流中每个包的方向
            flowpktsegs = splitFlowByDir(flowpktlens, flowpktdirs)  # 按照方向进行的划分
            flowlabels = [item[4] for item in flowdata]  # 流的标签
            groups.add([flowpktsegs, flowlabels, flowid])
        res[serverip] = groups.getGroup()
    saveDictToJson(res, savepath)
    # print("数量：",len(res["172.16.65.128"]))


def calGapsOfTss(tss):
    """
    计算时间间隔
    """
    if len(tss) == 1:
        return 0
    return [tss[i + 1] - tss[i] for i in range(len(tss) - 1)]


if __name__ == '__main__':
    # # 处理pcap文件，之后保存到数据
    # pcappaths=[r"../../data/cicaptdataset/raw/Phase1/1stPhase-timed-Merged.pcap",
    #     r"../../data/cicaptdataset/raw/Phase2/2ndPhase-timed-MergedV2.pcap"
    # ]
    # # pcappaths=[r"../../data/test/pcap/20241008.pcap"]
    # pktsavepath="../../data/cicaptdataset/processed/pktdata.csv"
    # readPcapAndSavePkt(pcappaths,pktsavepath)

    # # 打标记
    # labelpaths=[r"../../data/cicaptdataset/raw/Phase1/phase1_NetworkData.csv",r"../../data/cicaptdataset/raw/Phase2/phase2_NetworkData.csv"]
    # pktpath = "../../data/cicaptdataset/processed/pktdata.csv"
    # pktLableSavePath=r"../../data/cicaptdataset/processed/pktInfoLabled.csv"
    #
    # labelPkt(labelpaths,pktpath,pktLableSavePath)

    # # 进行聚合
    # datasetpath=r"../../data/cicaptdataset/processed/pktInfoLabled.csv"
    # flowpath=r"../../data/cicaptdataset/processed/flows.json"
    # aggrToFlow(datasetpath, flowpath)

    # # 按照服务器IP聚合
    # flowpath = r"../../data/cicaptdataset/processed/flows.json"
    # savepath = r"../../data/cicaptdataset/processed/serverIpFlows.json"
    # print("正在处理")
    # aggrToServerIp(flowpath,savepath)

    # # 按照服务器IP进行服务器指纹提取
    # servipath=r"../../data/cicaptdataset/processed/serverIpFlows.json"
    # # savepath=r"../../data/cicaptdataset/processed/serverIpFPGroupsFlowsTest.json"
    # savepath = r"../../data/cicaptdataset/processed/serverIpFPGroupsFlows.json"
    # calFingerByServerIp(servipath,savepath)

    # # 将服务器的IP进行特征标记
    # # 对分组的服务进行聚类(测试)
    # serverIpGDataPath = r"../../data/cicaptdataset/processed/serverIpFPGroupsFlows.json"
    # serverIpGData = readDictFromJson(serverIpGDataPath)
    # print("服务器IP数据读取完毕...")
    # flowPath = r"../../data/cicaptdataset/processed/flows.json"
    # flowdatas = readDictFromJson(flowPath)
    # print("流数据读取完毕...")
    # print("服务器的IP数量为：", len(serverIpGData))
    # print("流的数量为：", len(flowdatas))
    # feas=list()
    # ids=list()
    # labels=list()
    # flowFeas=dict()
    # for serverip, serverdata in serverIpGData.items():
    #     print("-----------------------------------")
    #     print("正在处理服务器IP：", serverip)
    #     for g_i, ser_g in enumerate(serverdata):
    #         ser_g_flow = ser_g["data"]
    #         ser_g_flowids = [item[0][2] for item in ser_g_flow]
    #         ser_g_labels=[item[0][1] for item in ser_g_flow]
    #         # 计算一个分组的特征
    #         # 1、分组id
    #         fea_id = g_i
    #         # 2、和大小相关的特征
    #         fea_flow_size = len(ser_g_flowids)  # 流的数量
    #         flowpkt_size = [mean([item[1] for item in flowdatas[flowid]]) for flowid in ser_g_flowids]  # 流中平均的每个流包大小
    #         fea_flowpkt_size_mean = mean(flowpkt_size)
    #         fea_flowpkt_size_std = std(flowpkt_size)
    #         # 3、和时间相关的特征
    #         time_flowlasttimes = [flowdatas[flowid][-1][0] - flowdatas[flowid][0][0] for flowid in ser_g_flowids]
    #         fea_time_flowlasttimes_mean = mean(time_flowlasttimes) #流持续时间均值
    #         fea_time_flowlasttimes_std = std(time_flowlasttimes)# 流持续时间标准差
    #         fea_time_flowtsgaps_mean=list()
    #         fea_time_flowtsgaps_std=list()
    #         for flowid in ser_g_flowids:
    #             flowid_ts=[flowdata[0] for flowdata in flowdatas[flowid]]
    #             flowid_tss=[flowid_ts[i+1] - flowid_ts[i] for i in range(len(flowid_ts) - 1)] if len(flowid_ts)>1 else 0
    #             flowid_tss_mean=mean(flowid_tss)
    #             flowid_tss_std=std(flowid_tss)
    #             fea_time_flowtsgaps_mean.append(flowid_tss_mean)
    #             fea_time_flowtsgaps_std.append(flowid_tss_std)
    #         fea_time_flowtsgaps_mean=mean(fea_time_flowtsgaps_mean) # 组内流中包时间间隔均值的均值
    #         fea_time_flowtsgaps_std=std(fea_time_flowtsgaps_std)# 组内流中包时间间隔标准差的标准差
    #         # 4、整体特征
    #         # ipnums=len(set([eval(item)[0] for item in ser_g_flowids]+[eval(item)[2] for item in ser_g_flowids]))
    #         # print(set([eval(item)[0] for item in ser_g_flowids]+[eval(item)[2] for item in ser_g_flowids])) # 实验数据集大部分都一个，这个特征没啥意义
    #         feas.append([fea_flow_size, float(fea_flowpkt_size_mean), float(fea_flowpkt_size_std),
    #                      float(fea_time_flowlasttimes_mean), float(fea_time_flowlasttimes_std)])
    #         ids.append(serverip+"_"+str(fea_id))
    #         labels.append(ser_g_labels)
    #         print([fea_flow_size, float(fea_flowpkt_size_mean), float(fea_flowpkt_size_std),
    #                      float(fea_time_flowlasttimes_mean), float(fea_time_flowlasttimes_std)])
    #         for flowid in ser_g_flowids:
    #             flowFeas[flowid]=[fea_id,[fea_flow_size, float(fea_flowpkt_size_mean), float(fea_flowpkt_size_std),
    #                      float(fea_time_flowlasttimes_mean), float(fea_time_flowlasttimes_std)],flowdatas[flowid][0][0]]
    # # saveDictToJson(flowFeas, r"../../data/cicaptdataset/processed/flowGIDFea.json")

    # # 聚类分析（想了想，在这里其实不合适）
    # # 各个维度按照统一聚类，结果可解释性不好
    # print(len(feas),len(ids),len(labels))
    # print(feas[0],ids[0],labels[0])
    # from sklearn.preprocessing import StandardScaler
    # scaler = StandardScaler()
    # X_scaled = scaler.fit_transform(feas)
    # clusterNum=20
    # kmeans = KMeans(n_clusters=clusterNum)  # 假设我们想要分成3个簇
    # print("正在聚类")
    # kmeans.fit(X_scaled)  # 使用标准化后的数据进行训练
    # kmeans_res=kmeans.labels_
    # res=[list() for _ in range(clusterNum)]
    # for i,i_res in enumerate(kmeans_res):
    #     res[i_res].append([feas[i],ids[i],set([i for item in labels[i] for i in item])])
    # print("聚类结果：")
    # for c_i,cluster in enumerate(res):
    #     print("----------------------------------")
    #     print("分组ID：",c_i)
    #     for s in cluster:
    #         print(s)

    # # 分析下一个分组中IP通信情况
    # serverIpGDataPath = r"../../data/cicaptdataset/processed/serverIpFPGroupsFlows.json"
    # serverIpGData = readDictFromJson(serverIpGDataPath)
    # print("服务器IP数据读取完毕...")
    # flowPath = r"../../data/cicaptdataset/processed/flows.json"
    # flowdatas = readDictFromJson(flowPath)
    # print("流数据读取完毕...")
    # print("服务器的IP数量为：", len(serverIpGData))
    # print("流的数量为：", len(flowdatas))
    # feas = list()
    # ids = list()
    # labels = list()
    # flowFeas = dict()
    # for serverip, serverdata in serverIpGData.items():
    #     print("-----------------------------------")
    #     print("正在处理服务器IP：", serverip)
    #     ipVisitG=dict()
    #     for g_i, ser_g in enumerate(serverdata):
    #         ser_g_flow = ser_g["data"]
    #         ser_g_flowids = [item[0][2] for item in ser_g_flow]
    #         ser_g_labels = [item[0][1] for item in ser_g_flow]
    #         ser_g_flowids_tss=[flowdatas[item][0][0] for item in ser_g_flowids]
    #         for i in range(len(ser_g_flowids)):
    #             srcip,srcport,dstip,dstport = eval(ser_g_flowids[i])
    #             if srcip not in ipVisitG:
    #                 ipVisitG[srcip] = list()
    #             ipVisitG[srcip].append([g_i,ser_g_flowids_tss[i]])
    #     # 排序list
    #     for srcip in ipVisitG.keys():
    #         ipVisitG[srcip] = sorted(ipVisitG[srcip], key=lambda x: x[1])
    #         for i in range(len(ipVisitG[srcip])-1,1,-1):
    #             ipVisitG[srcip][i][1]-=ipVisitG[srcip][i-1][1]
    #         ipVisitG[srcip][0][1] = 0
    #
    #     for srcip,srcdata in ipVisitG.items():
    #         print("................")
    #         print(srcip)
    #         print(srcdata)

    # # 计算下客户端IP通信情况
    # flowfeapath=r"../../data/cicaptdataset/processed/flowGIDFea.json"
    # flowfeadata=readDictFromJson(flowfeapath)
    # clientIpFlows=dict()
    # for flowid,flowfea in flowfeadata.items():
    #     srcip,srcport,dstip,dstport=eval(flowid)
    #     clientip=srcip
    #     # clientip=None
    #     # if srcport>dstport:
    #     #     clientip=srcip
    #     # else:
    #     #     clientip=dstip
    #     if clientip not in clientIpFlows:
    #         clientIpFlows[clientip]=dict()
    #     clientIpFlows[clientip][flowid]=flowfea
    # # 将每个客户端请求的流按照时间戳排序
    # for clientip in list(clientIpFlows.keys()):
    #     sorted_flows = sorted(clientIpFlows[clientip].items(), key=lambda item: item[1][2],reverse=False)
    #     clientIpFlows[clientip]=sorted_flows
    #
    # saveDictToJson(clientIpFlows, r"../../data/cicaptdataset/processed/clientIpFlows.json")

    # # 分析IP通信情况
    # clientIpFlowsFiles=r"../../data/cicaptdataset/processed/clientIpFlows.json"
    # clientIpFlows=readDictFromJson(clientIpFlowsFiles)
    # print("客户端情况读取完毕")
    # flowsFilepath=r"../../data/cicaptdataset/processed/flows.json"
    # flowdata=readDictFromJson(flowsFilepath)
    # print("流数据读取完毕")
    # for clientid,clientdatas in clientIpFlows.items():
    #     print("--------------------------------------")
    #     print("正在处理：",clientid)
    #     # 需要按照时间戳排序
    #     visitIp=dict()
    #     curts=0
    #     for flowid,flowfea in clientdatas:
    #         if "53" in flowid:
    #             continue
    #         print("....................")
    #         print(flowid)
    #         print(flowfea[:2])
    #         print(len(flowdata[flowid]),[item[1] for item in flowdata[flowid]][:30])
    #         label=set([item[4] for item in flowdata[flowid]])
    #         trans_protos=set([item[2] for item in flowdata[flowid]])
    #         print(label,trans_protos,flowdata[flowid][0][0],flowdata[flowid][0][0]-curts,flowdata[flowid][-1][0]-flowdata[flowid][0][0],mean([flowdata[flowid][i+1][0]-flowdata[flowid][i][0] for i in range(len(flowdata[flowid])-1) ]) if len(flowdata[flowid])>1 else 0,std([flowdata[flowid][i+1][0]-flowdata[flowid][i][0] for i in range(len(flowdata[flowid])-1) ])  if len(flowdata[flowid])>1 else 0)
    #         curts=flowdata[flowid][0][0]
    #         srcip,srcport,dstip,dstport=eval(flowid)
    #         if srcip not in visitIp:
    #             visitIp[srcip] = 1
    #         else:
    #             visitIp[srcip] += 1
    #         if dstip not in visitIp:
    #             visitIp[dstip] = 1
    #         else:
    #             visitIp[dstip] += 1
    #         del visitIp[clientid]
    #     print(visitIp)

    # # 分析客户端通信历史记录
    # clientIpFlowsFiles = r"../../data/cicaptdataset/processed/clientIpFlows.json"
    # clientIpFlows = readDictFromJson(clientIpFlowsFiles)
    # print("客户端情况读取完毕")
    # flowsFilepath = r"../../data/cicaptdataset/processed/flows.json"
    # flowdata = readDictFromJson(flowsFilepath)
    # print("流数据读取完毕")
    # for clientid, clientdatas in clientIpFlows.items():
    #     print("--------------------------------------")
    #     print("正在处理：", clientid)
    #     if clientid!="172.16.65.128":
    #         continue
    #     # 需要按照时间戳排序
    #     visitIp = dict()
    #     curts = 0
    #     ipVisit=list()
    #     for flowid, flowfea in clientdatas:
    #         # if "53" in flowid:
    #         #     continue
    #         # print("....................")
    #         srcip, srcport, dstip, dstport = eval(flowid)
    #         ipVisit.append([dstip,flowfea[2]])
    #
    #     ipVisit = sorted(ipVisit, key=lambda x: x[1], reverse=False)
    #     for i in range(len(ipVisit)-1,1,-1):
    #         ipVisit[i][1]-=ipVisit[i-1][1]
    #     ipVisit[0][1]=0
    #     print(ipVisit)

    # # 根据窗口绘制图
    # flowsFilepath = r"../../data/cicaptdataset/processed/flows.json"
    # flowdatas=readDictFromJson(flowsFilepath)
    # flowids=[flowid for flowid,_ in flowdatas.items()]
    # windowssize=10000
    # step=windowssize
    # import networkx as nx
    # for i in range(0,len(flowids),step):
    #     DG = nx.DiGraph()
    #     for j in range(windowssize):
    #         if i+j>=len(flowids):
    #             break
    #         srcip,srcport,dstip,dstport = eval(flowids[i+j])
    #         DG.add_edge(srcip, dstip)
    #     # 绘制图
    #     import matplotlib.pyplot as plt
    #
    #     pos = nx.spring_layout(DG)
    #     nx.draw_networkx(DG, pos, with_labels=True, arrows=True)
    #     plt.show()

    # 直接分类
    # # 1、首先从服务端发现可疑的流量
    # serverIpGDataPath = r"../../data/cicaptdataset/processed/serverIpFPGroupsFlows.json"
    # serverIpGData = readDictFromJson(serverIpGDataPath)
    # print("服务器IP数据读取完毕...")
    # flowPath = r"../../data/cicaptdataset/processed/flows.json"
    # flowdatas = readDictFromJson(flowPath)
    # print("流数据读取完毕...")
    # print("服务器的IP数量为：", len(serverIpGData))
    # print("流的数量为：", len(flowdatas))
    # res=list()
    # for serverip, serverdata in serverIpGData.items():
    #     print("-----------------------------------")
    #     print("正在处理服务器IP：", serverip)
    #     ipVisitG=dict()
    #     for g_i, ser_g in enumerate(serverdata):
    #         ser_g_flow = ser_g["data"]
    #         ser_g_flowids = [item[0][2] for item in ser_g_flow]
    #         ser_g_labels = [item[0][1] for item in ser_g_flow]
    #         ser_g_flowids_tss=[flowdatas[item][0][0] for item in ser_g_flowids]
    #         ser_g_flowids_pktnums=[len(flowdatas[item]) for item in ser_g_flowids]
    #         for i in range(len(ser_g_flowids)):
    #             srcip,srcport,dstip,dstport = eval(ser_g_flowids[i])
    #             if srcip not in ipVisitG:
    #                 ipVisitG[srcip] = list()
    #             ipVisitG[srcip].append([g_i,ser_g_flowids_tss[i],ser_g_flowids_pktnums])
    #     # 排序list
    #     for srcip in ipVisitG.keys():
    #         ipVisitG[srcip] = sorted(ipVisitG[srcip], key=lambda x: x[1])
    #         for i in range(len(ipVisitG[srcip])-1,1,-1):
    #             ipVisitG[srcip][i][1]-=ipVisitG[srcip][i-1][1]
    #         ipVisitG[srcip][0][1] = 0
    #
    #     for srcip,srcdata in ipVisitG.items():
    #         print("................")
    #         print(srcip,"，数量为：",len(srcdata))
    #         # print(srcdata)
    #
    #     # 判断，条件如下：
    #     # 1、如果只有一个流，流的数量少于等于3，那么没问题
    #     # 2、如果有多个流，其中有某个的流数量差别很大，那么有问题
    #     if len(ipVisitG)==1:
    #         for srcip,srcdata in ipVisitG.items():
    #             if len(srcdata)<=3:
    #                 continue
    #
    #     if len(ipVisitG)>1: # 判断流数量差别
    #         ipvisitNums=[len(item) for item in ipVisitG.values()]
    #         ips=[item for item in ipVisitG.keys()]
    #         for i in range(len(ipvisitNums)):
    #             cur_num=ipvisitNums[i]
    #             cur_ip=ips[i]
    #             paired=False
    #             for j in range(len(ipvisitNums)):
    #                 if j==i:
    #                     continue
    #                 pair_num=ipvisitNums[j]
    #                 if abs(pair_num-cur_num)<5:
    #                     paired=True
    #                     break
    #             if not paired:
    #                 res.append([cur_ip,serverip])
    # print("有问题的请求关系：",res)
    # saveDictToJson(res,"../../data/cicaptdataset/processed/serverdataClientVisitError.json")

    # # 2、检查异常客户端行为
    # clientIpFlowspath = "../../data/cicaptdataset/processed/clientIpFlows.json"
    # clientIpFlows = readDictFromJson(clientIpFlowspath)
    # serverdataClientVisitErrorPath = "../../data/cicaptdataset/processed/serverdataClientVisitError.json"
    # serverdataClientVisitData = {item[0]: item[1] for item in readDictFromJson(serverdataClientVisitErrorPath)}
    # errClientIps = list()
    # for clientip, clientdatas in clientIpFlows.items():
    #     if clientip not in serverdataClientVisitData:
    #         continue
    #     # 判断，如果客户端IP对应的服务器IP多，且杂乱，那么不能是攻击，因为要隐蔽
    #     serverIps = [eval(flowid)[2] for flowid, _ in clientdatas]
    #     if len(clientdatas) > 100 and len(set(serverIps)) > 3:
    #         continue
    #
    #     # 判断时间戳是不是有规律
    #     ts = [item[2] for _, item in clientdatas]
    #     tss = calGapsOfTss(ts)
    #     tssInt = [int(item) for item in tss]
    #     tssCounter = dict(Counter(tssInt))
    #     tssCounter_sortedByKeys = sorted(tssCounter.items(), key=lambda d: d[1], reverse=True)
    #     entropy = -sum(p * math.log2(p) for _, freq in tssCounter.items() for p in [freq / sum(tssInt)])
    #     if entropy > 0.01:
    #         continue
    #
    #     # 判断是不是行为比较杂乱，而且通信数据包量比较少
    #     errPktNumMean = list()
    #     if len(set(serverIps)) > 3:
    #         for flowid, flowfea in clientdatas:
    #             if serverdataClientVisitData[clientip] in flowid:
    #                 errPktNumMean.append(flowfea[1][0])
    #         if sum(errPktNumMean) <= 30:
    #             continue
    #
    #     # 剩下的是有问题的
    #     errClientIps.append([clientip, serverdataClientVisitData[clientip]])
    #     # print("---------------------------------")
    #     # print("正在处理客户端IP：", clientip, "有问题的服务器ID：", serverdataClientVisitData[clientip], "数量：",
    #     #       len(clientdatas))
    #     # print(tssCounter_sortedByKeys)
    #     # print(entropy)
    #     # for flowid, flowfea in clientdatas:
    #     #     print("流Id：", flowid)
    #     #     print("流特征：", flowfea)
    # saveDictToJson(errClientIps, "../../data/cicaptdataset/processed/errClientIps.json")

    # # 3、在有问题的IP中进一步过滤攻击流量
    # errClientIps=readDictFromJson("../../data/cicaptdataset/processed/errClientIps.json")
    # flowdata=readDictFromJson("../../data/cicaptdataset/processed/flows.json")
    # mal_flowids=list()
    # for csids in errClientIps:
    #     cIp,sIp=csids
    #     csids_flows=dict()
    #     for flowid,flowdata in flowdata.items():
    #         srcip,_,dstip,_=eval(flowid)
    #         if cIp==srcip and sIp==dstip:
    #             csids_flows[flowid]=flowdata
    #     print("---------------------------------")
    #     print("正在处理的异常对象是：",csids)
    #     print("内容：")
    #     flow_ts=list()
    #     flow_ids=list()
    #     flow_last_ts=list()
    #     flow_feas=dict()
    #     for flowid,flowdata in csids_flows.items():
    #         print("............")
    #         print(flowid)
    #         flowdata_ts=[item[0] for item in flowdata]
    #         # flowdata_tss=calGapsOfTss(flowdata_ts)
    #         flowdata_labels=[item[4] for item in flowdata]
    #         flow_ts.append(flowdata_ts[0])
    #         flow_ids.append(flowid)
    #         print(f"包数量：{len(flowdata)},标签：{set(flowdata_labels)}")
    #         print(f"持续时间:{flowdata_ts[-1]-flowdata_ts[-0]}")
    #         flow_last_ts.append(flowdata_ts[-1]-flowdata_ts[-0])
    #         if flowid not in flow_feas:
    #             flow_feas[flowid]=dict()
    #         flow_feas[flowid]["pktnum"]=len(flowdata)
    #     flow_tss=[[flowid,ts] for flowid,ts in zip(flow_ids,calGapsOfTss(flow_ts))]
    #     print("流间隔时间：",[flow_tss[i] for i in range(len(flow_tss))])
    #     errflowtss=[item for item in flow_tss if item[1] < 1000]
    #     print("用于判断的阈值：")
    #     for item in errflowtss:
    #         if flow_feas[item[0]]["pktnum"]>1000:
    #             continue
    #         print(item)
    #
    #     whiteids=list()
    #     # 判断攻击的，上面阈值判断小的是判断良性的，此外，包大的不能判定良性
    #     for item in errflowtss:
    #         if flow_feas[item[0]]["pktnum"]>1000:
    #             continue
    #         whiteids.append(item[0])
    #
    #     # 选择攻击的
    #     for item in flow_ids:
    #         if item not in whiteids:
    #             mal_flowids.append(item)
    # saveDictToJson(mal_flowids,"../../data/cicaptdataset/processed/judgeMalFlowids.json")

    # # 4、判断效果
    flowdata = readDictFromJson("../../data/cicaptdataset/processed/flows.json")
    judgeMaldata=readDictFromJson("../../data/cicaptdataset/processed/judgeMalFlowids.json")
    flowlabels=list()
    judgelabels=list()

    malFlowids=list()

    for flowid,flowdata in flowdata.items():
        pktnums=len(flowdata)
        if flowid not in judgeMaldata:
            judgelabels.extend([0]*pktnums)
        else:
            judgelabels.extend([1]*pktnums)
        flowdata_lables=set([str(item[4]) for item in flowdata])
        if len(flowdata_lables)>1:
            flowlabels.extend([1]*pktnums)
            malFlowids.append(flowid)
        else:
            flowlabels.extend([0]*pktnums)
    # 判断效果
    acc=accuracy_score(flowlabels, judgelabels)
    pre=precision_score(flowlabels, judgelabels)
    rec=recall_score(flowlabels, judgelabels)
    f1=f1_score(flowlabels, judgelabels)
    print("判定结果：")
    print("acc:",acc)
    print("pre:",pre)
    print("rec:",rec)
    print("f1:",f1)
    # print(malFlowids)




