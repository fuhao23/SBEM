from torch import nn


class SimpleCNN(nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super(SimpleCNN, self).__init__()
        # 网络结构
        self.conv1 = nn.Conv1d(in_channels=in_channels, out_channels=hidden_channels[0], kernel_size=3, padding=1)
        self.hiddenLayers = nn.ModuleList()
        for i in range(1, len(hidden_channels)):
            self.hiddenLayers.append(
                nn.Conv1d(in_channels=hidden_channels[i - 1], out_channels=hidden_channels[i], kernel_size=3,
                          padding=1))
        self.fc = nn.Linear(in_features=hidden_channels[-1], out_features=out_channels)
        self.relu = nn.ReLU()

    def forward(self, x):
        b_size = x.shape[0]
        x = x.unsqueeze(-1)
        x = self.relu(self.conv1(x))
        for layer in self.hiddenLayers:
            x = self.relu(layer(x))
        x = x.view(b_size, -1)
        x = self.fc(x)
        return x
