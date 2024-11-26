"""
计算时间戳的标记数据集
"""
import pandas as pd

from FileUtils import saveDictToJson

if __name__ == '__main__':
    datapath=[r"C:\Users\gswsf\Files\codes\paper\SP2025\data\cicaptdataset\raw\Phase1\phase1_NetworkData.csv",r"C:\Users\gswsf\Files\codes\paper\SP2025\data\cicaptdataset\raw\Phase2\phase2_NetworkData.csv"]
    res=list()
    for datapath in datapath:
        data=pd.read_csv(datapath)
        selected_columns = data[['ts','label','subLabel','subLabelCat']]
        result_list = selected_columns.values.tolist()
        res.extend(result_list)
    saveDictToJson(res,r"C:\Users\gswsf\Files\codes\paper\SP2025\data\cicaptdataset\processed\tsLables.json")