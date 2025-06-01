# SentinelDDoS (SentinelShield) - Advanced DDoS Protection Platform

SentinelDDoS (also known as SentinelShield) is a comprehensive cybersecurity solution designed to detect, analyze, and mitigate Distributed Denial of Service (DDoS) attacks in real-time. Built with a focus on performance and accuracy, the system employs advanced algorithms and machine learning techniques to identify and neutralize threats before they impact your infrastructure.

## 🚀 Key Features

- **Advanced Traffic Profiling**
  - Real-time traffic pattern analysis
  - Baseline behavior establishment
  - Protocol and payload inspection
  - Traffic flow correlation

- **Intelligent Anomaly Detection**
  - Entropy-based detection
  - Statistical analysis
  - Machine learning models
  - Adaptive thresholding

- **Automated Mitigation**
  - Dynamic rate limiting
  - IP reputation system
  - Behavioral blocking
  - Traffic shaping

- **Comprehensive Visualization**
  - Real-time threat dashboard
  - Historical analytics
  - Attack pattern recognition
  - Performance metrics

- **Advanced Attack Simulation**
  - Multiple attack vectors
  - Customizable parameters
  - Realistic traffic generation
  - Impact assessment

## Attack Simulation Types

SentinelShield supports various attack simulation modes:

1. **Distributed Flooding**: High-volume traffic from multiple sources
2. **Pulsing Attack**: Bursts of traffic followed by pauses
3. **Slowloris**: Slow HTTP headers to keep connections open
4. **SYN Flood**: TCP SYN packet flood simulation
5. **Mixed Distribution**: Varied attack vectors from many sources

Each attack type produces a unique threat pattern on the dashboard:
- **Flooding**: Sustained high threat level
- **Pulsing**: Alternating high/low threat levels
- **Slowloris**: Gradual increase in threat level
- **Distributed**: Chaotic, variable threat pattern

## 🔍 Data Analysis & Algorithms (DAA)

SentinelDDoS employs sophisticated algorithms and data analysis techniques to ensure accurate detection and mitigation of DDoS attacks:

### Core Algorithms

1. **Entropy Analysis**
   - Shannon entropy calculation for traffic randomness
   - Adaptive thresholding for anomaly detection
   - Protocol-specific entropy baselines

2. **Statistical Analysis**
   - Moving average calculations
   - Standard deviation monitoring
   - Z-score analysis for outlier detection
   - Time-series pattern recognition

3. **Machine Learning Models**
   - Supervised learning for attack classification
   - Unsupervised anomaly detection
   - Feature engineering for traffic patterns
   - Model training and validation pipelines

4. **Performance Optimization**
   - Efficient data structures for high-speed processing
   - Parallel processing for real-time analysis
   - Memory optimization techniques
   - Asynchronous I/O operations

## 🏗 System Architecture

SentinelDDoS is built on a modular architecture for maximum flexibility and scalability:

### Core Components

1. **Traffic Profiler** (`traffic_profiler.py`)
   - Traffic pattern analysis
   - Baseline establishment
   - Protocol analysis
   - Traffic classification

2. **Anomaly Detector** (`anomaly_detector.py`)
   - Entropy analysis
   - Statistical modeling
   - ML-based detection
   - Threshold management

3. **Mitigation Engine** (`mitigation.py`)
   - Rate limiting
   - IP blocking
   - Traffic filtering
   - Policy enforcement

4. **Attack Simulator** (`attack_simulator.py`)
   - Multiple attack vectors
   - Traffic generation
   - Attack customization
   - Impact simulation

### Web Interface
- **Dashboard**: Real-time monitoring
- **Simulator**: Attack simulation controls
- **Reports**: Historical analysis
- **Settings**: System configuration

## 🛠 Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge)
- 4GB RAM minimum (8GB recommended)
- 2 CPU cores minimum (4+ recommended)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SentinelDDoS.git
   cd SentinelDDoS
   ```

2. **Set up a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python -c "from app import create_app; app = create_app(); app.app_context().push(); from extensions import db; db.create_all()"
   ```

5. **Start the application**
   ```bash
   python app.py
   ```

6. **Access the web interface**
   Open your browser and navigate to: [http://localhost:5000](http://localhost:5000)

### Configuration

Edit `config.py` to customize settings:
- Database configuration
- Detection thresholds
- Mitigation policies
- Logging preferences
- API endpoints

## Usage

### Dashboard

The dashboard provides real-time visibility into your network traffic and security status:

- **Traffic Overview**: Monitor requests per second and unique IP addresses
- **Entropy Analysis**: Track statistical distribution of traffic
- **Anomaly Scores**: Real-time anomaly detection metrics
- **Threat Level Indicator**: Visual representation of current threat status
- **Top IPs**: List of IPs generating the most traffic

### Attack Simulator

The attack simulator allows you to test your detection and mitigation capabilities:

1. Navigate to the Simulator page
2. Select an attack type (Flooding, Pulsing, Slowloris, etc.)
3. Configure attack parameters (duration, intensity, IP distribution)
4. Start the attack simulation
5. Observe the effects on the dashboard
6. Test your mitigation strategies

### Settings

Customize the system to your specific needs:

- Adjust anomaly detection thresholds
- Configure mitigation policies
- Manage blocked IP addresses
- Set traffic profiling parameters

## Development

### Project Structure

- `app.py`: Main application and API endpoints
- `static/`: CSS, JavaScript, and other static assets
- `templates/`: HTML templates for the web interface
- `traffic_profiler.py`: Traffic analysis and profiling
- `anomaly_detector.py`: Anomaly detection algorithms
- `mitigation.py`: Attack mitigation strategies
- `attack_simulator.py`: Attack simulation logic
- `models.py`: Database models
- `db.py`: Database configuration

## 🧠 Algorithm Implementation Details

### Entropy-Based Detection
```python
def calculate_entropy(ip_frequencies, total_packets):
    """Calculate Shannon entropy for IP distribution"""
    entropy = 0.0
    for count in ip_frequencies.values():
        probability = count / total_packets
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy
```

### Statistical Analysis
- Moving average calculation for traffic baselining
- Standard deviation monitoring for anomaly detection
- Correlation analysis between different traffic metrics

### Machine Learning Pipeline
1. **Feature Extraction**
   - Packet rate analysis
   - Protocol distribution
   - Source IP distribution
   - Payload size patterns

2. **Model Training**
   - Supervised learning with labeled attack data
   - Cross-validation for model evaluation
   - Hyperparameter tuning

3. **Real-time Classification**
   - Low-latency prediction
   - Confidence scoring
   - Adaptive learning from new patterns

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📚 Resources

- [API Documentation](docs/API.md)
- [Developer Guide](docs/DEVELOPER.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🙏 Acknowledgements

SentinelDDoS stands on the shoulders of giants. We're grateful to the open-source community and the following projects:

- Flask and Flask extensions
- Scikit-learn and scientific Python stack
- D3.js and other visualization libraries
- Academic research in network security and anomaly detection

## 📞 Support

For support, please open an issue in the GitHub repository or contact us at support@sentinel-ddos.com

---

<div align="center">
  Made with ❤️ by the SentinelDDoS Team
</div>
