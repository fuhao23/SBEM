import numpy as np
import pandas as pd
from torch.utils.data import Dataset


class CICAptDataset(Dataset):

    def __init__(self, datapath, padding_len=784):
        self.padding_len = padding_len
        self.__load_data__(datapath)

    def __load_data__(self, datasetcsv):
        """
        构建加载数据集
        :param labelfilepath:
        :param pcapfilepath:
        :return:
        """
        print("正在加载数据集")
        self.dataset = pd.read_csv(datasetcsv)
        print("正在补齐数据")
        self.dataset["allpacket"] = self.dataset["allpacket"].where(self.dataset["allpacket"].str.len() > self.padding_len,self.dataset["allpacket"].str.ljust(self.padding_len, 'U'))
        self.dataset["allpacket"] = self.dataset["allpacket"].str.slice(0, self.padding_len)

        print("格式化标签")
        self.dataset["label"] = self.dataset["label"].astype("category")
        print("数据集加载完毕")

    def __len__(self):
        return len(self.dataset)

    def __getitem__(self, idx):
        decimal_pkt_array = np.array(
            list(map(lambda x: int(x, 16) if x != "U" else -1, self.dataset.loc[idx, "allpacket"])))
        return decimal_pkt_array, self.dataset.loc[idx, "label"]


if __name__ == '__main__':
    pass
