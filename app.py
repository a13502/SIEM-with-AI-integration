"""
Streamlit Dashboard for AI Security Log Analyzer
Main entry point for the web application
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.preprocessing import LogParser, FeatureEngineer
from src.models import IsolationForestDetector, OneClassSVMDetector, AutoencoderDetector, ModelTrainer

# Page configuration
st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .alert-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .anomaly-alert {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
    }
    .normal-alert {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'trained_model' not in st.session_state:
    st.session_state.trained_model = None
if 'model_type' not in st.session_state:
    st.session_state.model_type = None
if 'feature_columns' not in st.session_state:
    st.session_state.feature_columns = None
if 'parser' not in st.session_state:
    st.session_state.parser = LogParser()
if 'feature_engineer' not in st.session_state:
    st.session_state.feature_engineer = FeatureEngineer()

def main():
    st.markdown('<div class="main-header">🔒 AI Security Log Analyzer</div>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Model selection
        model_type = st.selectbox(
            "Select Model",
            ["Isolation Forest", "One-Class SVM", "Autoencoder"],
            help="Choose the anomaly detection model"
        )
        
        # Model parameters
        st.subheader("Model Parameters")
        if model_type == "Isolation Forest":
            contamination = st.slider("Contamination", 0.01, 0.5, 0.1, 0.01)
        elif model_type == "One-Class SVM":
            nu = st.slider("Nu (outlier fraction)", 0.01, 0.5, 0.1, 0.01)
        else:  # Autoencoder
            encoding_dim = st.slider("Encoding Dimension", 8, 64, 32, 8)
            epochs = st.slider("Training Epochs", 10, 100, 50, 10)
        
        st.markdown("---")
        
        # Data source
        st.subheader("Data Source")
        data_source = st.radio(
            "Choose data source",
            ["Upload CSV", "Use Sample Data", "Load from Dataset"],
            help="Select how to load log data"
        )
    
    # Main content area
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Data Analysis", "🤖 Train Model", "🔍 Detect Anomalies", "📈 Visualizations"])
    
    with tab1:
        show_data_analysis(data_source)
    
    with tab2:
        show_training(data_source, model_type, locals())
    
    with tab3:
        show_anomaly_detection()
    
    with tab4:
        show_visualizations()

def show_data_analysis(data_source):
    st.header("📊 Data Analysis")
    
    df = None
    
    if data_source == "Upload CSV":
        uploaded_file = st.file_uploader("Upload CSV log file", type=['csv'])
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                st.success(f"✅ Loaded {len(df)} records")
            except Exception as e:
                st.error(f"Error loading file: {str(e)}")
    
    elif data_source == "Use Sample Data":
        if st.button("Generate Sample Data"):
            with st.spinner("Generating sample network logs..."):
                df = st.session_state.parser.get_sample_data(n_samples=5000)
                st.session_state.sample_data = df
                st.success(f"✅ Generated {len(df)} sample records")
        
        if 'sample_data' in st.session_state:
            df = st.session_state.sample_data
    
    elif data_source == "Load from Dataset":
        st.info("💡 To use CICIDS2017 or UNSW-NB15 datasets, download them from their official websites and upload the CSV files.")
    
    if df is not None:
        st.subheader("Data Preview")
        st.dataframe(df.head(100), use_container_width=True)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Records", len(df))
        with col2:
            st.metric("Columns", len(df.columns))
        with col3:
            missing = df.isnull().sum().sum()
            st.metric("Missing Values", missing)
        with col4:
            if 'label' in df.columns:
                anomalies = (df['label'] != 'Normal').sum() if df['label'].dtype == 'object' else (df['label'] != 0).sum()
                st.metric("Anomalies", anomalies)
        
        st.subheader("Data Statistics")
        st.dataframe(df.describe(), use_container_width=True)
        
        # Store in session state
        st.session_state.raw_data = df

def show_training(data_source, model_type, local_vars):
    st.header("🤖 Train Model")
    
    if 'raw_data' not in st.session_state:
        st.warning("⚠️ Please load data in the 'Data Analysis' tab first.")
        return
    
    df = st.session_state.raw_data.copy()
    
    # Feature engineering
    st.subheader("Feature Engineering")
    with st.spinner("Creating features..."):
        df_features = st.session_state.feature_engineer.create_all_features(df)
        feature_cols = st.session_state.feature_engineer.get_feature_columns(df_features)
        st.session_state.feature_columns = feature_cols
        st.success(f"✅ Created {len(feature_cols)} features")
    
    # Prepare training data
    X = df_features[feature_cols].values
    
    # Train model
    st.subheader("Model Training")
    
    if st.button("🚀 Train Model", type="primary"):
        with st.spinner(f"Training {model_type}..."):
            try:
                if model_type == "Isolation Forest":
                    contamination = local_vars.get('contamination', 0.1)
                    model = IsolationForestDetector(contamination=contamination)
                    model.train(X)
                
                elif model_type == "One-Class SVM":
                    nu = local_vars.get('nu', 0.1)
                    model = OneClassSVMDetector(nu=nu)
                    model.train(X)
                
                else:  # Autoencoder
                    encoding_dim = local_vars.get('encoding_dim', 32)
                    epochs = local_vars.get('epochs', 50)
                    model = AutoencoderDetector(input_dim=X.shape[1], encoding_dim=encoding_dim)
                    model.train(X, epochs=epochs, batch_size=32)
                
                st.session_state.trained_model = model
                st.session_state.model_type = model_type
                st.session_state.processed_data = df_features
                
                st.success(f"✅ {model_type} trained successfully!")
                st.balloons()
                
            except Exception as e:
                st.error(f"Training failed: {str(e)}")
    
    if st.session_state.trained_model is not None:
        st.success(f"✅ Model ready: {model_type}")
        
        # Quick evaluation on training data
        if st.button("Evaluate on Training Data"):
            with st.spinner("Evaluating..."):
                predictions = st.session_state.trained_model.predict(X)
                scores = st.session_state.trained_model.predict_proba(X)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Anomalies Detected", int(predictions.sum()))
                with col2:
                    st.metric("Normal Detected", int((predictions == 0).sum()))
                with col3:
                    st.metric("Anomaly Rate", f"{predictions.mean():.2%}")

def show_anomaly_detection():
    st.header("🔍 Anomaly Detection")
    
    if st.session_state.trained_model is None:
        st.warning("⚠️ Please train a model in the 'Train Model' tab first.")
        return
    
    if 'processed_data' not in st.session_state:
        st.warning("⚠️ Please process data first.")
        return
    
    df = st.session_state.processed_data.copy()
    feature_cols = st.session_state.feature_columns
    X = df[feature_cols].values
    
    # Run detection
    if st.button("🔍 Run Detection", type="primary"):
        with st.spinner("Analyzing logs..."):
            predictions = st.session_state.trained_model.predict(X)
            scores = st.session_state.trained_model.predict_proba(X)
            
            df['prediction'] = predictions
            df['anomaly_score'] = scores
            
            st.session_state.detection_results = df
    
    if 'detection_results' in st.session_state:
        df_results = st.session_state.detection_results
        
        # Summary
        n_anomalies = int(df_results['prediction'].sum())
        n_normal = int((df_results['prediction'] == 0).sum())
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🚨 Anomalies Detected", n_anomalies, delta=f"{n_anomalies/len(df_results)*100:.1f}%")
        with col2:
            st.metric("✅ Normal Traffic", n_normal)
        with col3:
            avg_score = df_results['anomaly_score'].mean()
            st.metric("Average Anomaly Score", f"{avg_score:.3f}")
        
        # Alert threshold
        threshold = st.slider("Alert Threshold", 0.0, 1.0, 0.5, 0.1)
        high_risk = df_results[df_results['anomaly_score'] > threshold]
        
        if len(high_risk) > 0:
            st.markdown(f'<div class="alert-box anomaly-alert"><strong>🚨 High-Risk Alerts:</strong> {len(high_risk)} anomalies detected above threshold {threshold:.2f}</div>', unsafe_allow_html=True)
            
            st.subheader("High-Risk Anomalies")
            display_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'anomaly_score', 'prediction']
            display_cols = [col for col in display_cols if col in high_risk.columns]
            st.dataframe(high_risk[display_cols].head(100), use_container_width=True)
        else:
            st.markdown('<div class="alert-box normal-alert"><strong>✅ All Clear:</strong> No high-risk anomalies detected</div>', unsafe_allow_html=True)

def show_visualizations():
    st.header("📈 Visualizations")
    
    if 'detection_results' not in st.session_state:
        st.warning("⚠️ Please run anomaly detection first.")
        return
    
    df = st.session_state.detection_results
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Anomaly distribution
        fig1 = px.pie(
            values=[(df['prediction'] == 0).sum(), df['prediction'].sum()],
            names=['Normal', 'Anomaly'],
            title="Anomaly Distribution"
        )
        st.plotly_chart(fig1, use_container_width=True)
        
        # Anomaly score distribution
        fig2 = px.histogram(
            df,
            x='anomaly_score',
            color='prediction',
            title="Anomaly Score Distribution",
            nbins=50
        )
        st.plotly_chart(fig2, use_container_width=True)
    
    with col2:
        # Protocol distribution
        if 'protocol' in df.columns:
            fig3 = px.bar(
                df.groupby('protocol')['prediction'].sum().reset_index(),
                x='protocol',
                y='prediction',
                title="Anomalies by Protocol"
            )
            st.plotly_chart(fig3, use_container_width=True)
        
        # Top source IPs with anomalies
        if 'src_ip' in df.columns:
            top_ips = df[df['prediction'] == 1].groupby('src_ip').size().sort_values(ascending=False).head(10)
            fig4 = px.bar(
                x=top_ips.values,
                y=top_ips.index,
                orientation='h',
                title="Top 10 Source IPs with Anomalies"
            )
            st.plotly_chart(fig4, use_container_width=True)
    
    # Time series (if timestamp available)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_time = df.groupby(df['timestamp'].dt.hour)['prediction'].sum().reset_index()
        fig5 = px.line(
            df_time,
            x='timestamp',
            y='prediction',
            title="Anomalies Over Time (by Hour)"
        )
        st.plotly_chart(fig5, use_container_width=True)

if __name__ == "__main__":
    main()

