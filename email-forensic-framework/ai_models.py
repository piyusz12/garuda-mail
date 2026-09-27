import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
import numpy as np

class EmailAutoEncoder(nn.Module):
    """
    Stacked Autoencoder for Email Traffic Anomaly Detection.
    Architecture: input_dim -> 16 -> 8 -> 4 -> 8 -> 16 -> input_dim
    """
    def __init__(self, input_dim: int = 20):
        super().__init__()
        
        # Bottleneck forces the model to learn a compact representation of normal traffic
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4)
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim)
        )

    def forward(self, x):
        z = self.encoder(x)
        reconstruction = self.decoder(z)
        return reconstruction, z

def get_isolation_forest(random_state: int = 42) -> IsolationForest:
    """
    Initializes the Isolation Forest with starting hyperparameters.
    These should be tuned during calibration against the validation set.
    """
    return IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination="auto",
        random_state=random_state
    )

def calculate_reconstruction_error(original: np.ndarray, reconstructed: np.ndarray) -> np.ndarray:
    """
    Calculates the Mean Squared Error between the original PCA features 
    and the Autoencoder's reconstruction.
    """
    return np.mean(np.square(original - reconstructed), axis=1)