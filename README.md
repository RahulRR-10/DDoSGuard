# 🛡️ DDoSGuard

Advanced DDoS Detection and Mitigation System with Attack Simulation Capabilities

## Overview

DDoSGuard is a powerful tool for detecting and mitigating Distributed Denial of Service (DDoS) attacks using various algorithms, including traditional rate-based detection and machine learning approaches. It includes a user-friendly interface for analyzing network logs and a sophisticated attack simulation laboratory for testing detection mechanisms.

## Features

- **Multiple Detection Algorithms**:

  - Brute Force Detection
  - Optimized Sliding Window
  - Machine Learning (Isolation Forest)

- **Attack Simulation Lab**:

  - Distributed Attacks
  - Pulsing Attacks
  - Slowloris Attacks
  - SYN-Flood Attacks

- **Visualization and Analysis**:
  - Traffic distribution analysis
  - Request timeline visualization
  - Performance metrics
  - Attack pattern recognition

## Installation

1. Clone the repository or download the source code
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Running the Web Interface

To start the web application:

```bash
streamlit run app.py
```

This will open a browser window with the DDoSGuard interface.

### Using the Application

The application offers three main modes:

1. **Upload Logs**: Upload your own log files in CSV format with timestamp and source_ip columns
2. **Generate Logs**: Create synthetic log data with configurable attack intensity
3. **Simulate Attack**: Simulate specific attack types with detailed configuration options

### Command-line Log Generation

You can also generate attack logs from the command line using:

```bash
python generate_attack_logs.py --type distributed --duration 300 --intensity 10 --attackers 5 --output my_attack_logs.csv
```

Available attack types:

- `distributed`: Multiple sources sending at elevated rates
- `pulsing`: Traffic sent in waves to evade detection
- `slowloris`: Many connections maintained with minimal data
- `syn-flood`: Extremely high frequency connection attempts in bursts

## Detection Parameters

- **Threshold Requests**: Minimum number of requests in a time window to flag as attack
- **Time Window**: Period (in seconds) to count requests
- **Block Duration**: How long to block detected attackers

## Algorithm Comparison

| Algorithm                | Strengths                    | Weaknesses                                       |
| ------------------------ | ---------------------------- | ------------------------------------------------ |
| Brute Force              | Simple, no false negatives   | Slow on large datasets, O(n²)                    |
| Optimized Sliding Window | Fast, efficient memory use   | May miss some complex patterns                   |
| Machine Learning         | Can detect abnormal patterns | May have false positives, more compute intensive |

## Example Data

The repository includes example log data in `logs.csv` that demonstrates a typical distributed attack pattern for testing purposes.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
