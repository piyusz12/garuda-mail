import numpy as np
import torch
from typing import Dict, Any, List
from .models import EmailAutoEncoder, calculate_reconstruction_error
from .explainability import ModelExplainer

class AIPipeline:
    def __init__(self, manifest: Dict[str, Any], scaler, pca_model, if_model, ae_model: EmailAutoEncoder):
        self.manifest = manifest
        self.scaler = scaler
        self.pca = pca_model
        self.isolation_forest = if_model
        self.autoencoder = ae_model
        self.autoencoder.eval()
        
        # Weights for fusion
        self.w_if = 0.5
        self.w_ae = 0.5

    def normalize_score(self, raw_score: float, model_type: str) -> float:
        """
        Normalizes raw model outputs to a 0.0 - 1.0 range based on threshold calibrations.
        """
        threshold = self.manifest["thresholds"][model_type]
        # Simplified normalization: scaling around the established threshold
        normalized = min(max(raw_score / (threshold * 1.5), 0.0), 1.0)
        return round(normalized, 3)

    def run_ai(self, session_id: str, raw_features: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """
        Executes the Phase 6 anomaly detection pipeline for a single session.
        """
        # 1. Preprocessing (Scale features using baseline-fitted scaler)
        x_scaled = self.scaler.transform(raw_features.reshape(1, -1))
        
        # 2. Dimensionality Reduction (PCA)
        z_pca = self.pca.transform(x_scaled)
        
        # 3. Isolation Forest Inference
        # sklearn IF returns negative for anomalies, positive for normal. We invert it.
        if_raw_score = -self.isolation_forest.score_samples(z_pca)[0]
        if_norm = self.normalize_score(if_raw_score, "if")
        
        # 4. Autoencoder Inference
        with torch.no_grad():
            z_tensor = torch.FloatTensor(z_pca)
            reconstruction, latent = self.autoencoder(z_tensor)
            ae_error = calculate_reconstruction_error(z_pca, reconstruction.numpy())[0]
            ae_norm = self.normalize_score(ae_error, "ae")
            
        # 5. Score Fusion & Agreement
        combined_score = round((self.w_if * if_norm) + (self.w_ae * ae_norm), 3)
        model_agreement = round(1.0 - abs(if_norm - ae_norm), 3)
        
        # Classification thresholds
        classification = "NORMAL"
        if combined_score > self.manifest["thresholds"]["combined"]:
            classification = "ANOMALOUS" if combined_score < 0.90 else "HIGHLY_UNUSUAL"
            
        # 6. Explainability (Triggered conditionally for anomalies)
        explanation = {"top_features": []}
        if classification != "NORMAL":
            explainer = ModelExplainer(feature_names, self.pca.components_)
            explanation = explainer.explain_anomaly(raw_features.flatten(), if_norm, ae_norm)

        # 7. Construct Result JSON
        return {
            "session_id": session_id,
            "model_version": self.manifest["model_version"],
            "feature_schema_version": self.manifest["feature_schema"],
            "ai": {
                "isolation_forest_score": if_norm,
                "autoencoder_error": round(float(ae_error), 4),
                "combined_anomaly_score": combined_score,
                "model_agreement": model_agreement,
                "classification": classification
            },
            "explanation": explanation
        }