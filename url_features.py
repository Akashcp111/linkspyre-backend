"""
LINKSPYRE URL Feature Extraction Module

This module extracts comprehensive features from URLs for ML-based
malicious link detection. Features include:

1. URL Structure Features
   - URL length
   - Subdomain depth
   - Path depth
   - Query parameter count

2. Security Features
   - HTTPS usage
   - Port number
   - IP address presence

3. Suspicious Indicators
   - Suspicious keywords
   - URL shortener detection
   - Brand impersonation
   - Entropy score

4. Domain Features
   - Domain age indicators
   - TLD analysis
   - Character patterns
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
import ipaddress


class URLFeatureExtractor:
    """Extract features from URLs for ML classification"""
    
    # Suspicious keywords commonly used in phishing URLs
    SUSPICIOUS_KEYWORDS = [
        'secure', 'verify', 'update', 'account', 'login', 'signin',
        'confirm', 'validate', 'suspended', 'locked', 'unlock',
        'urgent', 'immediate', 'action', 'required', 'click',
        'phishing', 'malware', 'virus', 'trojan', 'spam'
    ]
    
    # Known URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly'
    ]
    
    # Popular brands often impersonated
    BRAND_KEYWORDS = [
        'amazon', 'paypal', 'microsoft', 'apple', 'google',
        'facebook', 'twitter', 'instagram', 'linkedin', 'netflix',
        'ebay', 'bank', 'chase', 'wells', 'fargo', 'citibank'
    ]
    
    def __init__(self):
        self.feature_names = self._get_feature_names()
    
    def extract_features(self, url: str, return_defaults: bool = True) -> dict:
        """
        Extract all features from a URL
        
        Args:
            url: The URL to analyze
            return_defaults: Whether to return default features on error
            
        Returns:
            Dictionary of feature names and values
        """
        try:
            parsed = urlparse(url)
        except:
            # Invalid URL - return default features
            if return_defaults:
                return self._get_default_features()
            return {}
        
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc) if parsed.netloc else 0
        features['path_length'] = len(parsed.path) if parsed.path else 0
        features['query_length'] = len(parsed.query) if parsed.query else 0
        
        # Structure features
        features['subdomain_depth'] = self._count_subdomains(parsed.netloc)
        features['path_depth'] = self._count_path_depth(parsed.path)
        features['num_query_params'] = len(parse_qs(parsed.query))
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_equals'] = url.count('=')
        features['num_question_marks'] = url.count('?')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        
        # Security features
        features['uses_https'] = 1 if parsed.scheme == 'https' else 0
        features['uses_http'] = 1 if parsed.scheme == 'http' else 0
        features['has_port'] = 1 if parsed.port else 0
        features['port_number'] = parsed.port if parsed.port else 0
        features['is_ip_address'] = 1 if self._is_ip_address(parsed.netloc) else 0
        
        # Suspicious indicators
        features['has_suspicious_keywords'] = self._has_suspicious_keywords(url.lower())
        features['num_suspicious_keywords'] = self._count_suspicious_keywords(url.lower())
        features['is_url_shortener'] = 1 if self._is_url_shortener(parsed.netloc) else 0
        features['has_brand_keyword'] = 1 if self._has_brand_keyword(url.lower()) else 0
        features['suspicious_tld'] = 1 if self._is_suspicious_tld(parsed.netloc) else 0
        
        # Character analysis
        features['entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(parsed.netloc) if parsed.netloc else 0
        features['has_mixed_case'] = 1 if self._has_mixed_case(url) else 0
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['num_special_chars'] = len([c for c in url if not c.isalnum() and c not in '.-/'])
        
        # Domain analysis
        if parsed.netloc:
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) >= 2:
                features['tld_length'] = len(domain_parts[-1])
                features['domain_name_length'] = len(domain_parts[-2]) if len(domain_parts) >= 2 else 0
            else:
                features['tld_length'] = 0
                features['domain_name_length'] = 0
        else:
            features['tld_length'] = 0
            features['domain_name_length'] = 0
        
        # Ratio features
        if features['url_length'] > 0:
            features['digit_ratio'] = features['num_digits'] / features['url_length']
            features['letter_ratio'] = features['num_letters'] / features['url_length']
            features['special_char_ratio'] = features['num_special_chars'] / features['url_length']
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0
            features['special_char_ratio'] = 0
        
        # Additional heuristics
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_double_slash'] = 1 if '//' in url[8:] else 0  # After http:// or https://
        features['path_has_extension'] = 1 if '.' in parsed.path.split('/')[-1] else 0
        
        return features
    
    def _count_subdomains(self, netloc: str) -> int:
        """Count number of subdomains"""
        if not netloc:
            return 0
        # Remove port if present
        netloc = netloc.split(':')[0]
        parts = netloc.split('.')
        # Subtract 1 for domain and TLD
        return max(0, len(parts) - 2)
    
    def _count_path_depth(self, path: str) -> int:
        """Count depth of URL path"""
        if not path or path == '/':
            return 0
        return len([p for p in path.split('/') if p])
    
    def _is_ip_address(self, netloc: str) -> bool:
        """Check if netloc is an IP address"""
        if not netloc:
            return False
        # Remove port if present
        netloc = netloc.split(':')[0]
        try:
            ipaddress.ip_address(netloc)
            return True
        except:
            return False
    
    def _has_suspicious_keywords(self, url: str) -> int:
        """Check if URL contains suspicious keywords"""
        return 1 if any(keyword in url for keyword in self.SUSPICIOUS_KEYWORDS) else 0
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """Count number of suspicious keywords in URL"""
        return sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword in url)
    
    def _is_url_shortener(self, netloc: str) -> int:
        """Check if domain is a known URL shortener (exact/netloc-based)"""
        if not netloc:
            return 0
        host = netloc.lower().split(':')[0]
        for s in self.URL_SHORTENERS:
            if host == s or host.endswith('.' + s):
                return 1
        return 0
    
    def _has_brand_keyword(self, url: str) -> int:
        """Check if URL contains brand keywords (potential impersonation)"""
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or '').lower().split(':')[0]
            sld = self._second_level_domain(host)
        except:
            host = ''
            sld = ''
        for brand in self.BRAND_KEYWORDS:
            if brand in url:
                # If the second-level domain exactly matches the brand, treat as legitimate
                if sld == brand:
                    continue
                return 1
        return 0

    def _second_level_domain(self, netloc: str) -> str:
        """Return second-level domain (e.g., 'example' from 'www.example.com')"""
        if not netloc:
            return ''
        parts = netloc.split('.')
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ''
    
    def _is_suspicious_tld(self, netloc: str) -> int:
        """Check for suspicious TLDs"""
        if not netloc:
            return 0
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        netloc = netloc.lower()
        return 1 if any(tld in netloc for tld in suspicious_tlds) else 0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        entropy = 0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
    
    def _has_mixed_case(self, text: str) -> int:
        """Check if text has mixed case"""
        return 1 if any(c.islower() for c in text) and any(c.isupper() for c in text) else 0
    
    def _get_default_features(self) -> dict:
        """Return default feature values for invalid URLs"""
        features = {}
        for name in self._get_feature_names():
            features[name] = 0
        return features
    
    def _get_feature_names(self) -> list:
        """Get list of all feature names"""
        # Create a dummy URL to extract feature names
        extractor = URLFeatureExtractor.__new__(URLFeatureExtractor)
        sample_features = extractor.extract_features('https://example.com/path?param=value')
        return list(sample_features.keys())
    
    def get_feature_vector(self, url: str) -> list:
        """
        Get feature vector as a list (for ML models)
        
        Args:
            url: The URL to analyze
            
        Returns:
            List of feature values in consistent order
        """
        features = self.extract_features(url)
        return [features[name] for name in self.feature_names]


if __name__ == '__main__':
    # Test the feature extractor
    extractor = URLFeatureExtractor()
    
    test_urls = [
        'https://www.example.com/path/to/page',
        'http://suspicious-site.tk/login/verify?account=locked',
        'https://bit.ly/abc123',
        'http://192.168.1.1:8080/admin'
    ]
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_features(url)
        print(f"Features extracted: {len(features)}")
        for key, value in sorted(features.items()):
            print(f"  {key}: {value}")

