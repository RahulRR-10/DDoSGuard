# SentinelShield - DDoS Detection and Mitigation System

SentinelShield is an advanced cybersecurity platform designed to detect, visualize, and mitigate DDoS attacks in real-time. The system combines traffic profiling, anomaly detection algorithms, and automated mitigation strategies to protect your infrastructure from various types of DDoS attacks.

## Features

- **Real-time Traffic Analysis**: Monitor network traffic patterns and detect anomalies as they occur
- **Interactive Dashboard**: Visual representation of traffic metrics, threat levels, and attack indicators
- **Attack Simulation Lab**: Test your detection systems with various attack types and configurations
- **Automated Mitigation**: Apply intelligent rate limiting and IP blocking strategies
- **Customizable Settings**: Adjust detection thresholds and mitigation policies to your needs
- **Comprehensive Reporting**: Generate detailed attack reports for post-analysis

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

## System Components

SentinelShield consists of several integrated components:

- **Traffic Profiler**: Analyzes network traffic and establishes normal behavior patterns
- **Anomaly Detector**: Uses entropy analysis, burst detection, and machine learning to identify abnormal traffic
- **Mitigation System**: Applies countermeasures to mitigate detected attacks
- **Attack Simulator**: Generates synthetic attack traffic for testing and training

## Installation

### Prerequisites

- Python 3.8+
- Flask
- SQLAlchemy
- NumPy, SciPy, scikit-learn
- Modern web browser (Chrome, Firefox, Edge)

### Setup

1. Clone the repository:
   ```
   git clone <repository-url>
   cd SentinelShield
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```
   python -c "from app import app; from db import db; app.app_context().push(); db.create_all()"
   ```

4. Start the application:
   ```
   python app.py
   ```

5. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

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

## License

[Specify license information here]

## Acknowledgements

SentinelShield incorporates several open-source libraries and research in the fields of network security, anomaly detection, and DDoS mitigation.
