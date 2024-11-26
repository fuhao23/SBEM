import json
import os


def saveDictToJson(data,path):
    """
    将数据保存文件
    :param data:
    :param path:
    :return:
    """
    with open(path,'w',encoding='utf-8') as f:
        json.dump(data,f)

def readDictFromJson(path):
    """
    从文件读取数据
    :param path:
    :return:
    """
    with open(path,'r',encoding='utf-8') as f:
        data = json.load(f)
    return data

def saveDictToJsonByLine(data,path):
    """
    按照每行将列表的文件存储
    :param data:
    :param path:
    :return:
    """
    with open(path,'w',encoding='utf-8') as f:
        for line in data:
            json.dump(line,f)
            f.write('\n')

def readDictFromJsonByLine(path):
    """
    按照每行一个对象解析文件
    :param path:
    :return:
    """
    datas=list()
    with open(path,'r',encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            datas.append(data)
    return datas

def lsFilesOfDir(dirpath):
    """
    获取文件夹路径下的文件路径
    :param dirpath:
    :return:
    """
    return os.listdir(dirpath)


if __name__ == '__main__':
    data=lsFilesOfDir("./data/cicaptdataset/raw/")
    print(data)