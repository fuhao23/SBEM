import torch
from torch.utils.data import random_split, DataLoader

from Model.cnn.dataset import CICAptDataset
from Model.cnn.evaluation import evaluation
from Model.cnn.model import SimpleCNN
from Model.cnn.train import train
from Model.cnn.utils import init_random

if __name__ == '__main__':
    # 首先设定随机化种子
    init_random()
    # 加载数据
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    datasetPath = "../../data/cicaptdataset/processed/pkttsslabeled.csv"
    feature_len = 784
    dataset = CICAptDataset(datasetPath, feature_len)
    testRate = 0.3
    trainsize = int(len(dataset) * testRate)
    testsize = len(dataset) - trainsize
    traindataset, testdataset = random_split(dataset, [trainsize, testsize])
    batch_size = 256
    train_loader = DataLoader(dataset=traindataset, batch_size=batch_size, shuffle=True,drop_last=True)
    test_loader = DataLoader(dataset=testdataset, batch_size=batch_size, shuffle=False)

    hiddenChannels = [256, 128, 64]
    step=1
    if step == 0:
        # 加载模型
        model = SimpleCNN(feature_len,hiddenChannels,2).to(device)
        criterion = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

        # 参数设置和训练
        epochnum=10
        train(model,criterion,optimizer,train_loader,epochnum,device)
    if step == 1:
        # 模型测试
        model=SimpleCNN(feature_len,hiddenChannels,2).to(device)
        model.load_state_dict(torch.load("./2024-09-25_16:04:24_cnnModel.pth"))
        evaluation(model,test_loader,device)

