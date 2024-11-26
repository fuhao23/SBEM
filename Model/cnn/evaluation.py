import torch
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


def evaluation(model, dataloader, device):
    """
    评价模型效果
    :return:
    """
    predicts = list()
    labels = list()
    model.eval()
    with torch.no_grad():
        for data_x, data_y in dataloader:
            data_x = data_x.to(torch.float32).to(device)
            data_y = data_y.to(device)
            output = model(data_x)
            predictLabel = torch.argmax(output, dim=1)
            predicts.extend(predictLabel.cpu().numpy().tolist())
            labels.extend(data_y.cpu().numpy().tolist())
    acc = accuracy_score(labels, predicts)
    pre = precision_score(labels, predicts)
    rec = recall_score(labels, predicts)
    f1 = f1_score(labels, predicts)

    print('Accuracy:', acc)
    print('Precision:', pre)
    print('Recall:', rec)
    print('F1:', f1)
