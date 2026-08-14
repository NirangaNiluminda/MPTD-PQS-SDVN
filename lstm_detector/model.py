import torch
import torch.nn as nn
from .config import FEATURE_DIM, HIDDEN_DIM, LATENT_DIM, NUM_LAYERS

class LSTMAEDetector(nn.Module):
    """
    Sequence-to-sequence LSTM Autoencoder with an explicit latent bottleneck.
    Input shape:  (batch, k, 6)   # [pos_x, pos_y, speed, heading, accel, tau_i]
    Output shape: (batch, k, 6) - reconstructed sequence

    hidden = LSTM hidden width (encoder/decoder internal state size)
    latent = compressed bottleneck width the encoder's final hidden state is
             projected down to before being expanded back out for decoding
             (Table 4.17 "Hidden" / "Latent" columns).
    """
    def __init__(self, feat_dim: int = FEATURE_DIM,
                 hidden: int = HIDDEN_DIM, latent: int = LATENT_DIM,
                 num_layers: int = NUM_LAYERS):
        super().__init__()
        self.feat_dim   = feat_dim
        self.hidden     = hidden
        self.latent     = latent
        self.num_layers = num_layers

        # Encoder: compress sequence to hidden state
        self.encoder = nn.LSTM(
            input_size=feat_dim, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )

        # Bottleneck: project hidden state down to the latent width and back up.
        # This is the actual "latent" representation reported in Table 4.17 —
        # without it, hidden and latent would always be the same number.
        self.to_latent   = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)

        # Decoder: reproduce sequence from the re-expanded bottleneck
        self.decoder = nn.LSTM(
            input_size=hidden, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )
        self.output_layer = nn.Linear(hidden, feat_dim)

    def forward(self, x: torch.Tensor):
        B, k, _ = x.shape

        # Encode - use final-layer hidden state as the pre-bottleneck summary
        _, (h_n, c_n) = self.encoder(x)

        # Compress to latent, then expand back to hidden width
        z = self.to_latent(h_n[-1])             # (B, latent)
        h_expanded = self.from_latent(z)         # (B, hidden)

        # Repeat the bottleneck as decoder input at each timestep
        decoder_input = h_expanded.unsqueeze(1).repeat(1, k, 1)  # (B, k, hidden)
        # Re-init decoder state from the post-bottleneck vector (h/c from the
        # encoder no longer apply cleanly once a bottleneck sits between them)
        h0 = h_expanded.unsqueeze(0).repeat(self.num_layers, 1, 1)
        c0 = torch.zeros_like(h0)
        decoded, _    = self.decoder(decoder_input, (h0, c0))
        reconstructed = self.output_layer(decoded)            # (B, k, feat_dim)
        return reconstructed