from datetime import datetime

import numpy as np
import torch
from torch import nn


def train(model, criterion, optimizer, train_loader, epochs, device):
    """
    模型训练
    :return:
    """
    train_loss=list()
    train_epochs_loss=list()
    for epoch in range(epochs):
        model.train()
        train_epoch_loss = list()
        for idx, (data_x, data_y) in enumerate(train_loader, 0):
            data_x = data_x.to(torch.float32).to(device)
            data_y = data_y.to(device)
            outputs = model(data_x)
            optimizer.zero_grad()
            loss = criterion(outputs, data_y)
            optimizer.step()
            train_epoch_loss.append(loss.item())
            train_loss.append(loss.item())
            if idx % (len(train_loader)//2) == 0:
                print(f"Epoch={epoch}/{epochs},{idx}/{len(train_loader)} of train,loss={loss.item()}")
        train_epochs_loss.append(np.average(train_epoch_loss))
    print("正在保存训练模型...")
    now = datetime.now()
    time_str = now.strftime("%Y-%m-%d_%H:%M:%S")
    torch.save(model.state_dict(), time_str+'_cnnModel.pth')