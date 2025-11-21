"""
Standalone script to train models on datasets
Command-line interface for training and evaluation
"""

import argparse
import pandas as pd
import numpy as np
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.preprocessing import LogParser, FeatureEngineer
from src.models import ModelTrainer


def main():
    parser = argparse.ArgumentParser(description='Train AI Security Log Analyzer models')
    parser.add_argument('--data', type=str, required=True, help='Path to CSV log file')
    parser.add_argument('--model', type=str, choices=['isolation_forest', 'one_class_svm', 'autoencoder', 'all'],
                       default='all', help='Model to train')
    parser.add_argument('--output', type=str, default='models/', help='Output directory for saved models')
    parser.add_argument('--test-split', type=float, default=0.2, help='Test set split ratio')
    parser.add_argument('--sample-data', action='store_true', help='Use sample generated data instead of file')
    parser.add_argument('--n-samples', type=int, default=10000, help='Number of samples to generate (if using sample data)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("AI Security Log Analyzer - Model Training")
    print("=" * 60)
    
    # Load data
    print("\n📊 Loading data...")
    log_parser = LogParser()
    feature_engineer = FeatureEngineer()
    
    if args.sample_data:
        print(f"Generating {args.n_samples} sample records...")
        df = log_parser.get_sample_data(n_samples=args.n_samples)
    else:
        print(f"Loading from {args.data}...")
        if 'cicids' in args.data.lower():
            df = log_parser.parse_cicids2017(args.data)
        elif 'unsw' in args.data.lower() or 'nb15' in args.data.lower():
            df = log_parser.parse_unsw_nb15(args.data)
        else:
            df = log_parser.parse_csv(args.data)
    
    print(f"✅ Loaded {len(df)} records with {len(df.columns)} columns")
    
    # Feature engineering
    print("\n🔧 Engineering features...")
    df_features = feature_engineer.create_all_features(df)
    feature_cols = feature_engineer.get_feature_columns(df_features)
    print(f"✅ Created {len(feature_cols)} features")
    
    # Prepare data
    X = df_features[feature_cols].values
    y = df_features['label'] if 'label' in df_features.columns else None
    
    # Split data
    split_idx = int(len(X) * (1 - args.test_split))
    X_train = X[:split_idx]
    X_test = X[split_idx:]
    y_test = y[split_idx:] if y is not None else None
    
    print(f"\n📈 Train set: {len(X_train)} samples")
    print(f"📈 Test set: {len(X_test)} samples")
    
    # Train models
    trainer = ModelTrainer()
    models_to_train = []
    
    if args.model == 'all':
        models_to_train = ['isolation_forest', 'one_class_svm', 'autoencoder']
    else:
        models_to_train = [args.model]
    
    print("\n🤖 Training models...")
    os.makedirs(args.output, exist_ok=True)
    
    for model_name in models_to_train:
        print(f"\n--- Training {model_name} ---")
        try:
            if model_name == 'isolation_forest':
                model = trainer.train_isolation_forest(X_train, contamination=0.1)
            elif model_name == 'one_class_svm':
                model = trainer.train_one_class_svm(X_train, nu=0.1)
            elif model_name == 'autoencoder':
                model = trainer.train_autoencoder(X_train, epochs=50, batch_size=32, encoding_dim=32)
            
            # Evaluate
            print(f"Evaluating {model_name}...")
            results = trainer.evaluate_model(model_name, X_test, y_test)
            
            # Print results
            print(f"\n📊 Results for {model_name}:")
            print(f"  Anomalies Detected: {results['n_anomalies']}")
            print(f"  Normal Detected: {results['n_normal']}")
            print(f"  Anomaly Rate: {results['anomaly_rate']:.2%}")
            
            if 'precision' in results:
                print(f"  Precision: {results['precision']:.4f}")
                print(f"  Recall: {results['recall']:.4f}")
                print(f"  F1-Score: {results['f1_score']:.4f}")
            
            # Save model
            model_path = os.path.join(args.output, f"{model_name}.pkl")
            trainer.save_model(model_name, model_path)
            print(f"  💾 Saved to {model_path}")
            
        except Exception as e:
            print(f"❌ Error training {model_name}: {str(e)}")
            import traceback
            traceback.print_exc()
    
    # Compare models
    if len(models_to_train) > 1:
        print("\n" + "=" * 60)
        print("📊 Model Comparison")
        print("=" * 60)
        comparison = trainer.compare_models(X_test, y_test)
        print(comparison.to_string(index=False))
        
        best_model = trainer.get_best_model('f1_score')
        print(f"\n🏆 Best Model (F1-Score): {best_model}")
    
    print("\n✅ Training complete!")


if __name__ == "__main__":
    main()

