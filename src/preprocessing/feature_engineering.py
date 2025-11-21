"""
Feature Engineering Module
Creates security-relevant features from log data
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from collections import Counter
import ipaddress


class FeatureEngineer:
    """Engineer features for security log analysis"""
    
    def __init__(self):
        self.feature_stats = {}
    
    def extract_ip_features(self, df: pd.DataFrame, ip_col: str = 'src_ip') -> pd.DataFrame:
        """
        Extract features from IP addresses
        
        Args:
            df: Input DataFrame
            ip_col: Column name containing IP addresses
            
        Returns:
            DataFrame with IP-based features
        """
        df = df.copy()
        
        if ip_col not in df.columns:
            return df
        
        # IP address entropy (uniqueness indicator)
        ip_counts = df[ip_col].value_counts()
        df[f'{ip_col}_entropy'] = df[ip_col].map(ip_counts)
        df[f'{ip_col}_is_private'] = df[ip_col].apply(
            lambda x: self._is_private_ip(x) if pd.notna(x) else False
        )
        
        # IP octet analysis
        df[f'{ip_col}_octet1'] = df[ip_col].apply(
            lambda x: int(x.split('.')[0]) if pd.notna(x) and '.' in str(x) else 0
        )
        
        return df
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    def extract_port_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract port-based features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with port features
        """
        df = df.copy()
        
        # Common port categories
        common_ports = [80, 443, 22, 21, 25, 53, 3306, 5432, 3389, 8080]
        
        if 'dst_port' in df.columns:
            df['dst_port_is_common'] = df['dst_port'].isin(common_ports)
            df['dst_port_is_high'] = df['dst_port'] > 49152
            df['dst_port_is_well_known'] = df['dst_port'] < 1024
        
        if 'src_port' in df.columns:
            df['src_port_is_ephemeral'] = (df['src_port'] >= 49152) & (df['src_port'] <= 65535)
        
        return df
    
    def extract_protocol_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract protocol-based features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with protocol features
        """
        df = df.copy()
        
        if 'protocol' in df.columns:
            # One-hot encode common protocols
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH']
            for protocol in protocols:
                df[f'protocol_{protocol}'] = (df['protocol'] == protocol).astype(int)
        
        return df
    
    def extract_temporal_features(self, df: pd.DataFrame, time_col: str = 'timestamp') -> pd.DataFrame:
        """
        Extract temporal features
        
        Args:
            df: Input DataFrame
            time_col: Column name containing timestamps
            
        Returns:
            DataFrame with temporal features
        """
        df = df.copy()
        
        if time_col not in df.columns:
            return df
        
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        
        df['hour'] = df[time_col].dt.hour
        df['day_of_week'] = df[time_col].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        
        return df
    
    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract network flow features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with flow features
        """
        df = df.copy()
        
        # Packet ratio features
        if 'fwd_packets' in df.columns and 'bwd_packets' in df.columns:
            df['packet_ratio'] = df['bwd_packets'] / (df['fwd_packets'] + 1)
            df['total_packets'] = df['fwd_packets'] + df['bwd_packets']
        
        # Byte ratio features
        if 'fwd_packet_bytes' in df.columns and 'bwd_packet_bytes' in df.columns:
            df['byte_ratio'] = df['bwd_packet_bytes'] / (df['fwd_packet_bytes'] + 1)
            df['total_bytes'] = df['fwd_packet_bytes'] + df['bwd_packet_bytes']
            df['avg_packet_size'] = df['total_bytes'] / (df['total_packets'] + 1)
        
        # Flow duration features
        if 'flow_duration' in df.columns:
            df['flow_duration_log'] = np.log1p(df['flow_duration'])
            df['flow_duration_normalized'] = (df['flow_duration'] - df['flow_duration'].mean()) / (df['flow_duration'].std() + 1)
        
        return df
    
    def extract_statistical_features(self, df: pd.DataFrame, group_by: List[str] = None) -> pd.DataFrame:
        """
        Extract statistical features grouped by specific columns
        
        Args:
            df: Input DataFrame
            group_by: Columns to group by for statistics
            
        Returns:
            DataFrame with statistical features
        """
        df = df.copy()
        
        if group_by is None:
            group_by = ['src_ip']
        
        # Ensure group_by columns exist
        group_by = [col for col in group_by if col in df.columns]
        
        if not group_by:
            return df
        
        # Calculate statistics per group
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        for col in numeric_cols:
            if col not in group_by:
                grouped = df.groupby(group_by)[col]
                df[f'{col}_mean'] = df[group_by[0]].map(grouped.mean())
                df[f'{col}_std'] = df[group_by[0]].map(grouped.std())
                df[f'{col}_max'] = df[group_by[0]].map(grouped.max())
        
        return df
    
    def create_all_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create all available features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with all engineered features
        """
        df = df.copy()
        
        # Apply all feature engineering steps
        df = self.extract_ip_features(df, 'src_ip')
        df = self.extract_ip_features(df, 'dst_ip')
        df = self.extract_port_features(df)
        df = self.extract_protocol_features(df)
        df = self.extract_temporal_features(df)
        df = self.extract_flow_features(df)
        
        # Statistical features
        if 'src_ip' in df.columns:
            df = self.extract_statistical_features(df, ['src_ip'])
        
        # Remove infinite and NaN values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        return df
    
    def get_feature_columns(self, df: pd.DataFrame, exclude_cols: List[str] = None) -> List[str]:
        """
        Get list of feature columns (exclude labels and IDs)
        
        Args:
            df: Input DataFrame
            exclude_cols: Additional columns to exclude
            
        Returns:
            List of feature column names
        """
        exclude_cols = exclude_cols or []
        
        # Default columns to exclude
        default_exclude = ['label', 'attack_category', 'flow_id', 'timestamp', 
                          'src_ip', 'dst_ip', 'service', 'hostname', 'message']
        
        exclude_cols = list(set(exclude_cols + default_exclude))
        
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        # Only numeric columns
        feature_cols = [col for col in feature_cols if df[col].dtype in [np.number, bool]]
        
        return feature_cols



