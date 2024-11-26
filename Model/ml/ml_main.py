"""
使用机器学习方法
"""
import time

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier


def createDatasetToCsv(datasetpaths, savepath):
    """
    构建数据集
    :return:
    """
    res = None
    for datasetpath in datasetpaths:
        print("正在处理：", datasetpath)
        data = pd.read_csv(datasetpath)
        del data["ts"]
        del data["Source IP"]
        del data["Destination IP"]
        del data["Source Port"]
        del data["Destination Port"]
        del data["Protocol Type"]
        del data["Protocol_name"]
        del data["subLabelCat"]
        del data["subLabel"]
        if res is None:
            res = data
        else:
            res = pd.concat([res, data], ignore_index=True)
    res.to_csv(savepath, index=False)


def ml(datasetpath):
    """
    机器学习分类
    :param datasetpath:
    :return:
    """
    data = pd.read_csv(datasetpath)
    X = data.iloc[:, :-1]  # 特征
    y = data.iloc[:, -1]  # 标签
    scaler = MinMaxScaler()
    X=scaler.fit_transform(X)
    # 将数据集分成训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 初始化分类器
    # clf = DecisionTreeClassifier()
    clf = RandomForestClassifier()
    # clf=SVC(kernel='linear')
    # 训练分类器
    time1=time.time()
    clf.fit(X_train, y_train)
    time2=time.time()
    # 预测测试集
    y_pred = clf.predict(X_test)
    time3=time.time()
    # 计算准确率
    accuracy = accuracy_score(y_test, y_pred)
    pre = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f'Accuracy: {accuracy}')
    print(f'Precision: {pre}')
    print(f'Recall: {rec}')
    print(f'F1: {f1}')
    print("训练时间：", time2-time1)
    print("预测时间：",time3-time2)

    """
    Accuracy: 0.9999956016930241
    Precision: 0.9894179894179894
    Recall: 0.9166666666666666
    F1: 0.9516539440203562
    训练时间： 4022.2446579933167 s
    预测时间： 16.161051988601685 s
    """



if __name__ == '__main__':
    # # 构建数据集
    datasetpaths = ["../../data/cicaptdataset/raw/phase1_NetworkData.csv",
                    "../../data/cicaptdataset/raw/phase2_NetworkData.csv"]
    savepath = "../../data/cicaptdataset/processed/ml_labels.csv"
    # createDatasetToCsv(datasetpaths,savepath)

    # 机器学习
    ml(savepath)
