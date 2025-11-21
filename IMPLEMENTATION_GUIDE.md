# Implementation Guide: AI-Powered SIEM

## 📁 Project Structure Overview

```
Ai-powered-siem/
├── app.py                    # Main Streamlit dashboard (web interface)
├── train_model.py            # Command-line training script
├── requirements.txt          # Python dependencies
├── README.md                 # User documentation
└── src/                      # Source code modules
    ├── __init__.py
    ├── preprocessing/        # Data processing modules
    │   ├── __init__.py
    │   ├── log_parser.py     # Parses different log formats
    │   └── feature_engineering.py  # Creates ML features
    └── models/               # ML model implementations
        ├── __init__.py
        ├── isolation_forest.py    # Isolation Forest model
        ├── one_class_svm.py       # One-Class SVM model
        ├── autoencoder.py         # Deep learning autoencoder
        └── model_trainer.py       # Training utilities
```

---

## 🎯 What Was Built

This is an **AI-powered Security Information and Event Management (SIEM) system** that:
1. Parses security logs from various formats
2. Engineers 50+ security-relevant features
3. Trains multiple ML models for anomaly detection
4. Provides a web dashboard for interactive analysis
5. Visualizes threats and anomalies

---

## 📝 Detailed Component Breakdown

### 1. **Main Application (`app.py`)**

**Location:** `app.py` (root directory)

**What it does:**
- Creates a Streamlit web dashboard with 4 tabs:
  - **Data Analysis**: Load and preview log data
  - **Train Model**: Train ML models with configurable parameters
  - **Detect Anomalies**: Run detection on loaded data
  - **Visualizations**: View charts and graphs

**Key Functions:**
- `main()`: Sets up the dashboard layout and sidebar
- `show_data_analysis()`: Handles data loading (CSV upload, sample data, or dataset)
- `show_training()`: Trains selected model with user parameters
- `show_anomaly_detection()`: Runs predictions and shows high-risk alerts
- `show_visualizations()`: Creates interactive charts using Plotly

**Why this design:**
- **Streamlit** was chosen for rapid web app development without HTML/CSS/JS
- **Session state** (`st.session_state`) preserves data between interactions
- **Tabs** organize workflow: load → train → detect → visualize
- **Sidebar** keeps configuration separate from main content

**To modify:**
- Add new tabs: Create new `show_*()` function and add to `st.tabs()`
- Change UI: Modify CSS in `st.markdown()` or add Streamlit widgets
- Add features: Extend session state variables and pass to functions

---

### 2. **Log Parser (`src/preprocessing/log_parser.py`)**

**Location:** `src/preprocessing/log_parser.py`

**What it does:**
- Parses CSV files, CICIDS2017, UNSW-NB15, and syslog formats
- Normalizes column names to standard format
- Generates sample data for testing
- Handles data type conversions

**Key Class:** `LogParser`

**Key Methods:**
- `parse_csv()`: Generic CSV parser
- `parse_cicids2017()`: Maps CICIDS2017 columns to standard names
- `parse_unsw_nb15()`: Maps UNSW-NB15 columns to standard names
- `parse_syslog()`: Basic syslog regex parsing
- `normalize_data()`: Converts timestamps, numeric columns, handles NaN
- `get_sample_data()`: Generates synthetic network logs for testing

**Why this design:**
- **Standardized column names** (`src_ip`, `dst_ip`, etc.) allow consistent feature engineering
- **Multiple format support** makes the system flexible for different data sources
- **Sample data generator** enables testing without real datasets

**To modify:**
- Add new format: Create `parse_*()` method following existing pattern
- Change column mappings: Update `column_mappings` dictionaries
- Improve sample data: Modify `get_sample_data()` to add more realistic patterns

---

### 3. **Feature Engineering (`src/preprocessing/feature_engineering.py`)**

**Location:** `src/preprocessing/feature_engineering.py`

**What it does:**
- Creates 50+ security-relevant features from raw logs
- Extracts IP, port, protocol, temporal, and flow features
- Calculates statistical aggregations per source IP

**Key Class:** `FeatureEngineer`

**Key Methods:**
- `extract_ip_features()`: IP entropy, private IP detection, octet analysis
- `extract_port_features()`: Port categories (well-known, ephemeral, high ports)
- `extract_protocol_features()`: One-hot encoding for protocols
- `extract_temporal_features()`: Hour, day of week, business hours, weekend flags
- `extract_flow_features()`: Packet/byte ratios, total counts, duration normalization
- `extract_statistical_features()`: Mean, std, max per source IP
- `create_all_features()`: Orchestrates all feature creation
- `get_feature_columns()`: Returns list of numeric feature columns (excludes labels/IDs)

**Why this design:**
- **Modular methods** allow selective feature creation
- **IP entropy** helps detect scanning/brute-force attacks
- **Port categories** identify suspicious port usage
- **Temporal features** detect time-based attack patterns
- **Flow statistics** capture communication patterns
- **Statistical aggregations** provide context per source IP

**To modify:**
- Add new features: Create new `extract_*()` method and call in `create_all_features()`
- Change feature logic: Modify existing extraction methods
- Exclude features: Update `get_feature_columns()` exclude list

---

### 4. **Isolation Forest Model (`src/models/isolation_forest.py`)**

**Location:** `src/models/isolation_forest.py`

**What it does:**
- Implements Isolation Forest anomaly detection
- Fast, unsupervised learning algorithm
- Good for large datasets

**Key Class:** `IsolationForestDetector`

**Key Methods:**
- `__init__()`: Sets contamination rate (expected anomaly proportion)
- `train()`: Fits model on training data with feature scaling
- `predict()`: Returns binary predictions (0=normal, 1=anomaly)
- `predict_proba()`: Returns normalized anomaly scores [0, 1]
- `save()`/`load()`: Model persistence

**Why this design:**
- **StandardScaler** normalizes features for better performance
- **Contamination parameter** controls sensitivity (0.1 = 10% expected anomalies)
- **Score normalization** converts negative scores to [0, 1] probabilities
- **Consistent interface** (predict/predict_proba) matches other models

**To modify:**
- Change parameters: Modify `__init__()` defaults or add new parameters
- Adjust scaling: Change `StandardScaler` to `MinMaxScaler` or `RobustScaler`
- Tune model: Modify `n_estimators`, `max_samples` in `IsolationForest()`

---

### 5. **One-Class SVM Model (`src/models/one_class_svm.py`)**

**Location:** `src/models/one_class_svm.py`

**What it does:**
- Implements One-Class SVM for anomaly detection
- Good for high-dimensional feature spaces
- Creates robust decision boundaries

**Key Class:** `OneClassSVMDetector`

**Key Methods:**
- `__init__()`: Sets `nu` (outlier fraction) and kernel type
- `train()`: Fits SVM with RBF kernel
- `predict()`: Binary predictions
- `predict_proba()`: Decision function scores normalized to [0, 1]

**Why this design:**
- **RBF kernel** handles non-linear patterns
- **Nu parameter** controls sensitivity (0.1 = 10% outliers expected)
- **Same interface** as Isolation Forest for easy swapping

**To modify:**
- Change kernel: Modify `kernel` parameter in `__init__()` ('linear', 'poly', 'sigmoid')
- Adjust gamma: Change `gamma` parameter for RBF kernel sensitivity
- Tune nu: Experiment with different outlier fractions

---

### 6. **Autoencoder Model (`src/models/autoencoder.py`)**

**Location:** `src/models/autoencoder.py`

**What it does:**
- Deep learning autoencoder for anomaly detection
- Learns to reconstruct normal patterns
- High reconstruction error = anomaly

**Key Classes:**
- `Autoencoder`: PyTorch neural network (encoder-decoder architecture)
- `AutoencoderDetector`: Wrapper with training/prediction logic

**Key Methods:**
- `__init__()`: Sets input dimension and encoding dimension
- `train()`: Trains with validation split, sets threshold at 95th percentile
- `predict()`: Uses reconstruction error threshold
- `predict_proba()`: Returns normalized reconstruction errors

**Architecture:**
```
Input → [128] → [64] → [encoding_dim] → [64] → [128] → Output
         (Encoder)                      (Decoder)
```

**Why this design:**
- **PyTorch** enables GPU acceleration (falls back to CPU automatically)
- **Validation split** prevents overfitting
- **95th percentile threshold** marks top 5% as anomalies
- **MSE loss** measures reconstruction quality
- **Adam optimizer** for efficient training

**To modify:**
- Change architecture: Modify `Autoencoder.__init__()` layers
- Adjust threshold: Change percentile in `train()` (currently 95)
- Tune hyperparameters: Modify epochs, batch_size, learning_rate
- Add dropout: Insert `nn.Dropout()` layers for regularization

---

### 7. **Model Trainer (`src/models/model_trainer.py`)**

**Location:** `src/models/model_trainer.py`

**What it does:**
- Orchestrates training of multiple models
- Evaluates models with metrics (precision, recall, F1)
- Compares models and selects best performer

**Key Class:** `ModelTrainer`

**Key Methods:**
- `train_isolation_forest()`: Wrapper for Isolation Forest training
- `train_one_class_svm()`: Wrapper for One-Class SVM training
- `train_autoencoder()`: Wrapper for Autoencoder training
- `evaluate_model()`: Calculates metrics if labels available
- `compare_models()`: Creates comparison DataFrame
- `get_best_model()`: Returns best model by metric
- `save_model()`/`load_model()`: Model persistence

**Why this design:**
- **Unified interface** for all models
- **Automatic evaluation** when labels are available
- **Model comparison** helps choose best algorithm
- **Flexible metrics** (precision, recall, F1-score)

**To modify:**
- Add metrics: Extend `evaluate_model()` with new metrics
- Change comparison: Modify `compare_models()` to include different metrics
- Add ensemble: Create method to combine multiple models

---

### 8. **Command-Line Training (`train_model.py`)**

**Location:** `train_model.py` (root directory)

**What it does:**
- Standalone script for training models from command line
- Supports all three models or individual training
- Saves models to disk

**Key Features:**
- Argument parsing for data path, model selection, output directory
- Automatic dataset format detection (CICIDS2017, UNSW-NB15)
- Model comparison and best model selection

**Why this design:**
- **CLI interface** for automation and scripting
- **Batch processing** without web UI overhead
- **Model persistence** for production deployment

**To modify:**
- Add arguments: Extend `argparse` with new options
- Change defaults: Modify default values in `add_argument()`
- Add preprocessing: Insert data cleaning steps before feature engineering

---

### 9. **Module Initialization Files**

**Locations:**
- `src/__init__.py`: Package version
- `src/preprocessing/__init__.py`: Exports `LogParser`, `FeatureEngineer`
- `src/models/__init__.py`: Exports all model classes

**What they do:**
- Make modules importable as `from src.preprocessing import LogParser`
- Define public API of each package

**Why this design:**
- **Clean imports** without exposing internal structure
- **Python package structure** for maintainability

**To modify:**
- Add exports: Add to `__all__` list in respective `__init__.py`
- Change imports: Update import statements in other files

---

## 🔄 Data Flow

```
1. Raw Logs (CSV/syslog)
   ↓
2. LogParser.parse_*() → Normalized DataFrame
   ↓
3. FeatureEngineer.create_all_features() → Feature-rich DataFrame
   ↓
4. Extract feature columns → NumPy array (X)
   ↓
5. Model.train(X) → Trained model
   ↓
6. Model.predict(X) → Predictions (0/1)
   ↓
7. Model.predict_proba(X) → Anomaly scores [0, 1]
   ↓
8. Visualization & Alerts
```

---

## 🛠️ Common Modification Scenarios

### Adding a New ML Model

1. **Create model file:** `src/models/new_model.py`
   ```python
   class NewModelDetector:
       def __init__(self, param1=value):
           ...
       def train(self, X):
           ...
       def predict(self, X):
           ...
       def predict_proba(self, X):
           ...
   ```

2. **Export in `src/models/__init__.py`:**
   ```python
   from .new_model import NewModelDetector
   __all__ = [..., 'NewModelDetector']
   ```

3. **Add to `ModelTrainer` (`src/models/model_trainer.py`):**
   ```python
   def train_new_model(self, X_train, param1=value):
       model = NewModelDetector(param1=param1)
       model.train(X_train)
       self.models['new_model'] = model
       return model
   ```

4. **Add to Streamlit UI (`app.py`):**
   - Add to model selection dropdown
   - Add parameter sliders in sidebar
   - Add training logic in `show_training()`

---

### Adding New Features

1. **Create method in `FeatureEngineer` (`src/preprocessing/feature_engineering.py`):**
   ```python
   def extract_new_features(self, df):
       df = df.copy()
       # Your feature logic here
       df['new_feature'] = ...
       return df
   ```

2. **Call in `create_all_features()`:**
   ```python
   df = self.extract_new_features(df)
   ```

---

### Changing Model Parameters

**Isolation Forest:**
- File: `src/models/isolation_forest.py`
- Change: `contamination`, `n_estimators`, `max_samples` in `__init__()`

**One-Class SVM:**
- File: `src/models/one_class_svm.py`
- Change: `nu`, `kernel`, `gamma` in `__init__()`

**Autoencoder:**
- File: `src/models/autoencoder.py`
- Change: `encoding_dim`, layer sizes in `Autoencoder.__init__()`
- Change: `epochs`, `batch_size`, `learning_rate` in `train()`

---

### Adding New Visualizations

1. **File:** `app.py`
2. **Function:** `show_visualizations()`
3. **Add new Plotly chart:**
   ```python
   fig = px.scatter(df, x='feature1', y='feature2', color='prediction')
   st.plotly_chart(fig, use_container_width=True)
   ```

---

### Supporting New Log Format

1. **File:** `src/preprocessing/log_parser.py`
2. **Add method:**
   ```python
   def parse_new_format(self, file_path):
       df = self.parse_csv(file_path)
       # Map columns to standard names
       column_mappings = {...}
       df = df.rename(columns=column_mappings)
       return df
   ```

3. **Update `app.py` or `train_model.py`** to call new parser

---

## 🎨 Design Decisions Explained

### Why Streamlit?
- **Rapid prototyping**: No frontend code needed
- **Interactive widgets**: Built-in sliders, file uploaders, charts
- **Session state**: Maintains data between interactions
- **Easy deployment**: `streamlit run app.py` and it works

### Why Three Different Models?
- **Isolation Forest**: Fast, good baseline
- **One-Class SVM**: Handles complex boundaries
- **Autoencoder**: Deep learning for subtle patterns
- **User choice**: Different models work better for different data

### Why Feature Engineering?
- **Raw logs aren't ML-ready**: Need numeric features
- **Domain knowledge**: Security-specific features (IP entropy, port categories)
- **Better detection**: Engineered features improve model performance

### Why Modular Design?
- **Separation of concerns**: Parser, features, models are independent
- **Easy testing**: Test each component separately
- **Reusability**: Use models without UI, or parser without models
- **Maintainability**: Changes in one area don't break others

---

## 📚 Key Files Reference

| File | Purpose | Key to Modify For |
|------|---------|-------------------|
| `app.py` | Web dashboard | UI changes, new tabs, visualizations |
| `train_model.py` | CLI training | Batch processing, automation |
| `log_parser.py` | Data loading | New log formats, data cleaning |
| `feature_engineering.py` | Feature creation | New features, feature selection |
| `isolation_forest.py` | IF model | Model tuning, parameters |
| `one_class_svm.py` | OCSVM model | Model tuning, parameters |
| `autoencoder.py` | Autoencoder model | Architecture, training loop |
| `model_trainer.py` | Training utilities | Evaluation metrics, model comparison |

---

## 🚀 Quick Start for Modifications

1. **Understand the flow**: Data → Features → Model → Predictions
2. **Identify the component**: Which file handles your change?
3. **Check dependencies**: What other files import this module?
4. **Test incrementally**: Make small changes and test
5. **Update documentation**: Keep this guide current

---

## 💡 Tips for Future Development

- **Add logging**: Use Python's `logging` module for debugging
- **Add unit tests**: Create `tests/` directory with pytest
- **Add configuration file**: Use YAML/JSON for model parameters
- **Add model versioning**: Track model versions and performance
- **Add database**: Store detection results in SQLite/PostgreSQL
- **Add API**: Create Flask/FastAPI endpoint for programmatic access
- **Add real-time processing**: Stream logs instead of batch processing
- **Add alerting**: Send notifications (email, Slack) on high-risk anomalies

---

This guide should help you navigate and modify the codebase effectively. If you need to make changes, refer to the relevant section above!

