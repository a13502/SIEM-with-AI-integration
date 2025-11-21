"""
Log Parser Module
Handles parsing of various log formats (CSV, syslog, etc.)
"""

import pandas as pd
import numpy as np
from typing import Optional, List, Dict
import re
from datetime import datetime


class LogParser:
    """Parse and normalize log files for security analysis"""
    
    def __init__(self):
        self.supported_formats = ['csv', 'json', 'syslog']
    
    def parse_csv(self, file_path: str, **kwargs) -> pd.DataFrame:
        """
        Parse CSV log file
        
        Args:
            file_path: Path to CSV file
            **kwargs: Additional pandas read_csv parameters
            
        Returns:
            DataFrame with parsed logs
        """
        try:
            df = pd.read_csv(file_path, **kwargs)
            return df
        except Exception as e:
            raise ValueError(f"Error parsing CSV: {str(e)}")
    
    def parse_cicids2017(self, file_path: str) -> pd.DataFrame:
        """
        Parse CICIDS2017 dataset format
        
        Args:
            file_path: Path to CICIDS2017 CSV file
            
        Returns:
            DataFrame with normalized columns
        """
        df = self.parse_csv(file_path, low_memory=False)
        
        # Common CICIDS2017 column mappings
        column_mappings = {
            'Flow ID': 'flow_id',
            'Source IP': 'src_ip',
            'Destination IP': 'dst_ip',
            'Source Port': 'src_port',
            'Destination Port': 'dst_port',
            'Protocol': 'protocol',
            'Timestamp': 'timestamp',
            'Flow Duration': 'flow_duration',
            'Total Fwd Packets': 'fwd_packets',
            'Total Backward Packets': 'bwd_packets',
            'Total Length of Fwd Packets': 'fwd_packet_bytes',
            'Total Length of Bwd Packets': 'bwd_packet_bytes',
            'Label': 'label'
        }
        
        # Rename columns if they exist
        df = df.rename(columns={k: v for k, v in column_mappings.items() if k in df.columns})
        
        return df
    
    def parse_unsw_nb15(self, file_path: str) -> pd.DataFrame:
        """
        Parse UNSW-NB15 dataset format
        
        Args:
            file_path: Path to UNSW-NB15 CSV file
            
        Returns:
            DataFrame with normalized columns
        """
        df = self.parse_csv(file_path, low_memory=False)
        
        # Common UNSW-NB15 column mappings
        column_mappings = {
            'srcip': 'src_ip',
            'dstip': 'dst_ip',
            'sport': 'src_port',
            'dsport': 'dst_port',
            'proto': 'protocol',
            'state': 'state',
            'dur': 'flow_duration',
            'label': 'label',
            'attack_cat': 'attack_category'
        }
        
        df = df.rename(columns={k: v for k, v in column_mappings.items() if k in df.columns})
        
        return df
    
    def parse_syslog(self, file_path: str) -> pd.DataFrame:
        """
        Parse syslog format (basic implementation)
        
        Args:
            file_path: Path to syslog file
            
        Returns:
            DataFrame with parsed log entries
        """
        logs = []
        
        # Basic syslog regex pattern
        syslog_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<service>\S+):\s+'
            r'(?P<message>.*)'
        )
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = syslog_pattern.match(line.strip())
                if match:
                    logs.append(match.groupdict())
        
        df = pd.DataFrame(logs)
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        return df
    
    def normalize_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize column names and data types
        
        Args:
            df: Input DataFrame
            
        Returns:
            Normalized DataFrame
        """
        df = df.copy()
        
        # Convert timestamp columns
        timestamp_cols = [col for col in df.columns if 'time' in col.lower() or 'date' in col.lower()]
        for col in timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Convert numeric columns
        numeric_cols = [col for col in df.columns if any(x in col.lower() for x in ['port', 'packet', 'byte', 'duration', 'count', 'size'])]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Handle missing values
        df = df.replace([np.inf, -np.inf], np.nan)
        
        return df
    
    def get_sample_data(self, n_samples: int = 1000) -> pd.DataFrame:
        """
        Generate sample log data for testing
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            DataFrame with sample network logs
        """
        np.random.seed(42)
        
        data = {
            'src_ip': [f"192.168.1.{np.random.randint(1, 255)}" for _ in range(n_samples)],
            'dst_ip': [f"10.0.0.{np.random.randint(1, 255)}" for _ in range(n_samples)],
            'src_port': np.random.randint(1024, 65535, n_samples),
            'dst_port': np.random.choice([80, 443, 22, 21, 25, 53, 3306], n_samples),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
            'flow_duration': np.random.exponential(1000, n_samples),
            'fwd_packets': np.random.poisson(10, n_samples),
            'bwd_packets': np.random.poisson(5, n_samples),
            'fwd_packet_bytes': np.random.poisson(1000, n_samples),
            'bwd_packet_bytes': np.random.poisson(500, n_samples),
            'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='1min')
        }
        
        df = pd.DataFrame(data)
        
        # Add labels (mostly normal, some anomalies)
        anomaly_indices = np.random.choice(n_samples, size=int(n_samples * 0.1), replace=False)
        df['label'] = 'Normal'
        df.loc[anomaly_indices, 'label'] = 'Anomaly'
        
        return df



