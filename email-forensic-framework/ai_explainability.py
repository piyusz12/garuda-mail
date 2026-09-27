import numpy as np
from typing import List, Dict, Any

class ModelExplainer:
    """
    Handles explainability for the AI pipeline, translating latent/PCA space
    anomalies back to human-readable original features using SHAP principles.
    """
    def __init__(self, feature_names: List[str], pca_components: np.ndarray):
        self.feature_names = feature_names
        self.pca_components = pca_components
        
    def explain_anomaly(self, original_features: np.ndarray, if_score: float, ae_error: float) -> Dict[str, Any]:
        """
        Generates feature contributions for anomalous sessions.
        Note: In a production environment, this would invoke actual SHAP TreeExplainer 
        for Isolation Forest and DeepExplainer for the Autoencoder. 
        """
        # Mocking SHAP logic for the prototype pipeline
        # In reality, this calculates the SHAP values and maps them via the inverse PCA matrix
        
        # Simulated feature attributions based on variance (for demonstration)
        feature_importance = np.abs(original_features - np.mean(original_features)) 
        
        # Sort indices by highest deviation/importance
        top_indices = np.argsort(feature_importance)[-4:][::-1]
        
        top_features = []
        for idx in top_indices:
            feat_name = self.feature_names[idx]
            # Mock SHAP value direction
            contribution = round(float(feature_importance[idx] * 0.1), 2)
            top_features.append({
                "feature": feat_name,
                "contribution": f"+{contribution}"
            })
            
        return {
            "top_features": [f["feature"] for f in top_features],
            "detailed_contributions": top_features
        }