import torch
import torch.nn as nn
from .config import FEATURE_DIM, HIDDEN_DIM, NUM_LAYERS

class LSTMAEDetector(nn.Module):
    """
    Sequence-to-sequence LSTM Autoencoder.
    Input shape:  (batch, k, 5)
    Output shape: (batch, k, 5) - reconstructed sequence
    """
    def __init__(self, feat_dim: int = FEATURE_DIM,
                 hidden: int = HIDDEN_DIM, num_layers: int = NUM_LAYERS):
        super().__init__()
        self.feat_dim   = feat_dim
        self.hidden     = hidden
        self.num_layers = num_layers

        # Encoder: compress sequence to hidden state bottleneck
        self.encoder = nn.LSTM(
            input_size=feat_dim, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )

        # Decoder: reproduce sequence from hidden state bottleneck
        self.decoder = nn.LSTM(
            input_size=hidden, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )
        self.output_layer = nn.Linear(hidden, feat_dim)

    def forward(self, x: torch.Tensor):
        B, k, _ = x.shape

        # Encode - use final hidden state as bottleneck
        _, (h_n, c_n) = self.encoder(x)

        # Repeat the bottleneck hidden state as decoder input at each step
        decoder_input = h_n[-1].unsqueeze(1).repeat(1, k, 1)  # (B, k, hidden)
        decoded, _    = self.decoder(decoder_input, (h_n, c_n))
        reconstructed = self.output_layer(decoded)            # (B, k, feat_dim)
        return reconstructed
