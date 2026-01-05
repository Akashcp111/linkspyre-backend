"""
LINKSPYRE Dataset Utilities

Helper functions for downloading and processing datasets from:
- PhishTank
- OpenPhish
- URLHaus
- Kaggle

This module provides utilities for academic dataset preparation.
"""

import requests
import pandas as pd
import os
from typing import List, Tuple
import csv


class DatasetDownloader:
    """Download and process datasets from various sources"""
    
    @staticmethod
    def download_phishtank(output_file: str = 'data/phishtank.csv'):
        """
        Download PhishTank dataset
        
        Note: PhishTank requires API key for programmatic access.
        For academic use, download manually from: https://www.phishtank.com/
        """
        print("PhishTank dataset download:")
        print("1. Visit https://www.phishtank.com/")
        print("2. Register for API access")
        print("3. Download phishing URLs")
        print(f"4. Save to {output_file}")
        return False
    
    @staticmethod
    def download_openphish(output_file: str = 'data/openphish.txt'):
        """
        Download OpenPhish dataset
        
        OpenPhish provides a free feed at:
        https://openphish.com/feed.txt
        """
        try:
            url = 'https://openphish.com/feed.txt'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(response.text)
                print(f"Downloaded OpenPhish dataset to {output_file}")
                return True
            else:
                print(f"Failed to download OpenPhish: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error downloading OpenPhish: {e}")
            return False
    
    @staticmethod
    def download_urlhaus(output_file: str = 'data/urlhaus.csv'):
        """
        Download URLHaus dataset
        
        URLHaus provides CSV downloads at:
        https://urlhaus.abuse.ch/downloads/csv/
        """
        try:
            url = 'https://urlhaus.abuse.ch/downloads/csv/'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                print(f"Downloaded URLHaus dataset to {output_file}")
                return True
            else:
                print(f"Failed to download URLHaus: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error downloading URLHaus: {e}")
            return False
    
    @staticmethod
    def process_kaggle_dataset(filepath: str, url_column: str = 'url', 
                              label_column: str = 'label') -> pd.DataFrame:
        """
        Process a Kaggle dataset file
        
        Args:
            filepath: Path to Kaggle dataset CSV
            url_column: Name of URL column
            label_column: Name of label column
            
        Returns:
            Processed DataFrame
        """
        try:
            df = pd.read_csv(filepath)
            
            # Ensure required columns exist
            if url_column not in df.columns:
                raise ValueError(f"URL column '{url_column}' not found")
            
            # Filter valid URLs
            df = df[df[url_column].notna()]
            df = df[df[url_column].str.startswith(('http://', 'https://'))]
            
            return df[[url_column, label_column]]
        except Exception as e:
            print(f"Error processing Kaggle dataset: {e}")
            return pd.DataFrame()


def create_balanced_dataset(malicious_files: List[str], 
                           safe_files: List[str],
                           output_file: str = 'data/balanced_dataset.csv',
                           max_samples_per_class: int = 10000):
    """
    Create a balanced dataset from multiple sources
    
    Args:
        malicious_files: List of file paths containing malicious URLs
        safe_files: List of file paths containing safe URLs
        output_file: Output file path
        max_samples_per_class: Maximum samples per class
    """
    malicious_urls = []
    safe_urls = []
    
    # Load malicious URLs
    for filepath in malicious_files:
        if os.path.exists(filepath):
            try:
                if filepath.endswith('.csv'):
                    df = pd.read_csv(filepath)
                    if 'url' in df.columns:
                        urls = df['url'].tolist()
                    else:
                        urls = df.iloc[:, 0].tolist()
                elif filepath.endswith('.txt'):
                    with open(filepath, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                else:
                    continue
                
                malicious_urls.extend(urls)
                print(f"Loaded {len(urls)} malicious URLs from {filepath}")
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
    
    # Load safe URLs
    for filepath in safe_files:
        if os.path.exists(filepath):
            try:
                if filepath.endswith('.csv'):
                    df = pd.read_csv(filepath)
                    if 'url' in df.columns:
                        urls = df['url'].tolist()
                    else:
                        urls = df.iloc[:, 0].tolist()
                elif filepath.endswith('.txt'):
                    with open(filepath, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                else:
                    continue
                
                safe_urls.extend(urls)
                print(f"Loaded {len(urls)} safe URLs from {filepath}")
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
    
    # Limit samples
    malicious_urls = malicious_urls[:max_samples_per_class]
    safe_urls = safe_urls[:max_samples_per_class]
    
    # Create balanced dataset
    df = pd.DataFrame({
        'url': malicious_urls + safe_urls,
        'label': [1] * len(malicious_urls) + [0] * len(safe_urls)
    })
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    
    print(f"\nCreated balanced dataset:")
    print(f"  Total URLs: {len(df)}")
    print(f"  Malicious: {len(malicious_urls)}")
    print(f"  Safe: {len(safe_urls)}")
    print(f"  Saved to: {output_file}")
    
    return df


if __name__ == '__main__':
    print("LINKSPYRE Dataset Utilities")
    print("="*50)
    
    # Example: Download OpenPhish
    downloader = DatasetDownloader()
    downloader.download_openphish()
    
    print("\nFor academic use, consider:")
    print("1. PhishTank: https://www.phishtank.com/")
    print("2. OpenPhish: https://openphish.com/")
    print("3. URLHaus: https://urlhaus.abuse.ch/")
    print("4. Kaggle: Search for 'phishing URLs' or 'malicious URLs'")

