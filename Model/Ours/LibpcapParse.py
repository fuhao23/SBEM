import ctypes as ct
import struct

import LibpcapParse as pcap
import LibpcapParse
import ctypes

from LibpcapParse import pkthdr


def find_all_devices():
    """
    查询所有的网络接口
    :return:
    """
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    alldevs = ct.POINTER(pcap.pcap_if_t)()  # 创建设备指针

    # 查找所有设备
    if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
        print("Error finding devices:", errbuf.value.decode())
    else:
        print("Devices available:")
        current_dev = alldevs.contents  # 获取第一个设备
        while current_dev:
            print(current_dev.name.decode())  # 打印设备名称
            # 移动到下一个设备
            current_dev = current_dev.next  # 获取下一个设备指针
            if current_dev:
                current_dev = current_dev.contents  # 访问下一个设备的内容

    # 释放资源
    pcap.freealldevs(alldevs)


# 定义回调函数的类型
CALLBACK_TYPE = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pkthdr), ct.POINTER(ct.c_ubyte))


# 数据包处理函数
def packet_handler(user, header, packet):
    # 解析数据包
    packet_len = header.contents.len
    packet_data = ct.string_at(packet, packet_len)
    # 解析以太网层
    eth_header = struct.unpack("!6s6sH", packet_data[:14])
    mac_src = ":".join(f'{item:02x}' for item in eth_header[0])
    mac_dst = ":".join(f'{item:02x}' for item in eth_header[1])
    iptype = f'{eth_header[2]:04x}'
    packet_data = packet_data[14:]
    # 解析IP层
    if iptype == "0800":
        if packet_len < 20:
            print("IP头部太少了！")
            return
        ipheader = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", packet_data[:20])
        ip_version = int.from_bytes(ipheader[0])>>4
        ip_hdr_len= (int.from_bytes(ipheader[0])%16)*4 # 单位是字节
        dsf=ipheader[1]
        total_len=ipheader[2]
        identification = ipheader[3]
        flags = ipheader[4]
        ttl=ipheader[5]
        protocol = ipheader[6]
        



if __name__ == '__main__':
    device_name = "\\Device\\NPF_{AAFA073C-56E9-4365-BF0A-0BA7726302DE}"
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    handle = pcap.open_live(device_name.encode(), 65535, 1, 1000, errbuf)
    if not handle:
        print("Error opening device:", errbuf.value.decode())
        exit(1)

    print("Starting packet capture...")
    packet_handler_c = CALLBACK_TYPE(packet_handler)
    pcap.loop(handle, 10, packet_handler_c, None)
    pcap.close(handle)
    print("Packet capture finished.")
