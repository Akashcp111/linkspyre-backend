"""
LINKSPYRE Model Inference Module

This module loads trained ML models and performs real-time
URL classification for the API endpoint.
"""

import joblib
import numpy as np
import os
import json
from .url_features import URLFeatureExtractor


class URLRiskClassifier:
    """Load and use trained models for URL risk classification"""
    
    def __init__(self, models_dir=None):
        if models_dir is None:
            # Use absolute path relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.models_dir = os.path.join(base_dir, 'models')
        else:
            self.models_dir = models_dir
            
        self.models = {}
        self.feature_extractor = None
        self.feature_names = None
        self.load_models()
    
    def load_models(self):
        """Load trained models and feature extractor"""
        try:
            # Load feature extractor
            extractor_path = os.path.join(self.models_dir, 'feature_extractor.pkl')
            if os.path.exists(extractor_path):
                self.feature_extractor = joblib.load(extractor_path)
            else:
                # Fallback to new extractor
                self.feature_extractor = URLFeatureExtractor()
            
            # Load feature names
            feature_names_path = os.path.join(self.models_dir, 'feature_names.json')
            if os.path.exists(feature_names_path):
                with open(feature_names_path, 'r') as f:
                    self.feature_names = json.load(f)
            else:
                self.feature_names = self.feature_extractor.feature_names
            
            # Load Random Forest model
            rf_path = os.path.join(self.models_dir, 'random_forest_model.pkl')
            if os.path.exists(rf_path):
                self.models['random_forest'] = joblib.load(rf_path)
                print(f"Loaded Random Forest model from {rf_path}")
            
            # Load XGBoost model
            xgb_path = os.path.join(self.models_dir, 'xgboost_model.pkl')
            if os.path.exists(xgb_path):
                self.models['xgboost'] = joblib.load(xgb_path)
                print(f"Loaded XGBoost model from {xgb_path}")
            
            if not self.models:
                print("WARNING: No trained models found. Using default classifier.")
                self._create_default_classifier()
                
        except Exception as e:
            print(f"Error loading models: {e}")
            self._create_default_classifier()
    
    def _create_default_classifier(self):
        """Create a default rule-based classifier if models are not available"""
        print("Using default rule-based classifier")
        self.feature_extractor = URLFeatureExtractor()
        self.feature_names = self.feature_extractor.feature_names
    
    def predict(self, url: str) -> dict:
        """
        Predict risk score and classification for a URL
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with:
            - risk_score: 0-100 risk score
            - classification: 'safe', 'suspicious', or 'malicious'
            - reasons: List of risk indicators
            - features: Extracted features
        """
        # Extract features
        features = self.feature_extractor.extract_features(url)
        feature_vector = np.array([features[name] for name in self.feature_names]).reshape(1, -1)
        
        # Get predictions from all available models
        predictions = []
        probabilities = []
        
        for name, model in self.models.items():
            try:
                proba = model.predict_proba(feature_vector)[0]
                predictions.append(model.predict(feature_vector)[0])
                probabilities.append(proba[1] if len(proba) > 1 else proba[0])
            except Exception as e:
                print(f"Error with {name} model: {e}")
        
        # Ensemble prediction: average probabilities
        if probabilities:
            avg_probability = np.mean(probabilities)
            risk_score = int(avg_probability * 100)
        else:
            # Fallback to rule-based scoring
            risk_score = self._rule_based_score(features)
        
        # Determine classification
        if risk_score >= 71:
            classification = 'malicious'
        elif risk_score >= 31:
            classification = 'suspicious'
        else:
            classification = 'safe'
        
        # Generate reasons
        reasons = self._generate_reasons(features, risk_score)
        
        return {
            'risk_score': risk_score,
            'classification': classification,
            'reasons': reasons,
            'features': features,
            'model_confidence': float(np.mean(probabilities)) if probabilities else 0.5
        }
    
    def _rule_based_score(self, features: dict) -> int:
        """Fallback rule-based scoring if models are not available"""
        score = 0
        
        # High risk indicators
        if features.get('is_url_shortener', 0) == 1:
            score += 20
        if features.get('is_ip_address', 0) == 1:
            score += 15
        if features.get('has_suspicious_keywords', 0) == 1:
            score += 25
        if features.get('num_suspicious_keywords', 0) > 2:
            score += 15
        if features.get('suspicious_tld', 0) == 1:
            score += 20
        if features.get('uses_http', 0) == 1 and features.get('uses_https', 0) == 0:
            score += 10
        if features.get('subdomain_depth', 0) > 3:
            score += 10
        if features.get('entropy', 0) > 4.5:
            score += 10
        
        # Medium risk indicators
        if features.get('has_brand_keyword', 0) == 1:
            score += 15
        if features.get('path_depth', 0) > 5:
            score += 5
        if features.get('num_query_params', 0) > 5:
            score += 5
        
        return min(100, score)
    
    def _generate_reasons(self, features: dict, risk_score: int) -> list:
        """Generate human-readable reasons for the risk score"""
        reasons = []
        
        if features.get('is_url_shortener', 0) == 1:
            reasons.append('URL shortener detected (often used to hide malicious links)')
        
        if features.get('is_ip_address', 0) == 1:
            reasons.append('Direct IP address (bypasses domain reputation)')
        
        if features.get('has_suspicious_keywords', 0) == 1:
            keyword_count = features.get('num_suspicious_keywords', 0)
            reasons.append(f'Suspicious keywords detected ({keyword_count} found)')
        
        if features.get('suspicious_tld', 0) == 1:
            reasons.append('Suspicious top-level domain (high risk TLD)')
        
        if features.get('uses_http', 0) == 1 and features.get('uses_https', 0) == 0:
            reasons.append('Unencrypted connection (HTTP instead of HTTPS)')
        
        if features.get('subdomain_depth', 0) > 3:
            reasons.append('Excessive subdomain depth (potential obfuscation)')
        
        if features.get('has_brand_keyword', 0) == 1:
            reasons.append('Brand keyword detected (possible impersonation)')
        
        if features.get('entropy', 0) > 4.5:
            reasons.append('High entropy (random-looking URL structure)')
        
        if features.get('num_query_params', 0) > 5:
            reasons.append('Excessive query parameters (potential data exfiltration)')
        
        if features.get('path_depth', 0) > 5:
            reasons.append('Deep path structure (unusual URL structure)')
        
        # If no specific reasons, provide generic ones based on score
        if not reasons:
            if risk_score >= 71:
                reasons.append('High risk score indicates potential malicious activity')
            elif risk_score >= 31:
                reasons.append('Moderate risk indicators detected')
            else:
                reasons.append('No significant risk indicators found')
        
        return reasons


# Global classifier instance (loaded once at startup)
_classifier_instance = None

def get_classifier():
    """Get or create global classifier instance"""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = URLRiskClassifier()
    return _classifier_instance

