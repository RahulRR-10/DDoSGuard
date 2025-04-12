import pandas as pd
import numpy as np
from collections import defaultdict, deque, Counter
import random, time
import matplotlib.pyplot as plt
import streamlit as st
from datetime import datetime
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def generate_fake_logs(n=1000, attack_intensity=5):
    """
    Generate realistic log data with adjustable attack patterns
    
    Parameters:
    - n: number of log entries
    - attack_intensity: 1-10 scale where higher means more concentrated attacks
    """
    logs = []
    # Generate more realistic IP ranges
    legitimate_ips = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}" for i in range(20)]
    attacker_ips = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for i in range(5)]
    
    # Generate timestamps with realistic patterns
    current_time = int(time.time())
    timestamps = []
    
    # Regular traffic with slight randomness
    for i in range(n):
        # Add some randomness to create more realistic intervals
        interval = random.uniform(0.5, 3)
        if timestamps:
            timestamps.append(timestamps[-1] + interval)
        else:
            timestamps.append(current_time)
    
    # Create attack patterns
    attack_windows = []
    num_attacks = max(1, n // 500)  # More logs = more attacks
    
    for _ in range(num_attacks):
        attack_start = random.randint(0, n-100)
        attack_duration = random.randint(50, 200)
        attack_windows.append((attack_start, attack_start + attack_duration))
    
    # Generate the final logs
    for i in range(n):
        # Check if current index is in an attack window
        in_attack = any(start <= i <= end for start, end in attack_windows)
        
        if in_attack:
            # During attack, select attacker IPs more frequently based on intensity
            weight_legitimate = max(1, 10 - attack_intensity)
            weights = [weight_legitimate] * len(legitimate_ips) + [attack_intensity * 3] * len(attacker_ips)
            ip_list = legitimate_ips + attacker_ips
            ip = random.choices(ip_list, weights=weights)[0]
        else:
            # Normal traffic
            ip = random.choice(legitimate_ips)
        
        logs.append((timestamps[i], ip))
    
    df = pd.DataFrame(logs, columns=["timestamp", "source_ip"])
    return df


def detect_ddos(logs, T, threshold, algo="Optimized Sliding Window"):
    """
    Wrapper to select and run the appropriate DDoS detection algorithm.
    
    Parameters:
    - logs: DataFrame with timestamp and source_ip columns
    - T: Time window in seconds
    - threshold: Number of requests to consider as attack
    - algo: Detection algorithm to use
    
    Returns:
    - list of detected attacker IPs
    - execution time
    """
    start = time.time()

    if algo == "Brute Force":
        attackers = brute_force_detection(logs, T, threshold)
    elif algo == "Optimized Sliding Window":
        attackers = optimized_detection(logs, T, threshold)
    elif algo == "Machine Learning (Beta)":
        attackers = ml_detection(logs, T, threshold)
    else:
        raise ValueError(f"Unknown algorithm selected: {algo}")

    elapsed = time.time() - start
    return attackers, elapsed


def brute_force_detection(logs, T, threshold):
    """
    Simple brute force detection that compares every log entry with every other
    entry to count requests within the time window.
    
    O(n²) complexity, but guaranteed to find all attackers.
    """
    count = defaultdict(int)
    logs = logs.values.tolist()
    
    # For each log entry
    for i in range(len(logs)):
        ts_i, ip_i = logs[i]
        
        # Count all requests from the same IP within time window T
        for j in range(len(logs)):
            ts_j, ip_j = logs[j]
            if ip_i == ip_j and 0 <= ts_j - ts_i <= T:
                count[ip_i] += 1
    
    # Return IPs that exceed the threshold
    return [ip for ip, c in count.items() if c > threshold]


def optimized_detection(logs, T, threshold):
    """
    Optimized sliding window detection with O(n) complexity.
    Uses a deque to efficiently track requests within the time window.
    """
    # Sort logs by timestamp to ensure proper window sliding
    logs = logs.sort_values("timestamp").reset_index(drop=True)
    window = deque()
    counter = defaultdict(int)
    attack_frequency = defaultdict(int)  # Track attack frequency over time
    attackers = set()

    for _, row in logs.iterrows():
        timestamp, ip = row["timestamp"], row["source_ip"]

        # Remove old entries outside the time window
        while window and timestamp - window[0][0] > T:
            old_time, old_ip = window.popleft()
            counter[old_ip] -= 1

        # Add current entry to window
        window.append((timestamp, ip))
        counter[ip] += 1

        # Check if current IP exceeds threshold
        if counter[ip] > threshold:
            attackers.add(ip)
            attack_frequency[ip] += 1

    # Apply weighted scoring for more accurate detection
    # IPs that exceeded the threshold multiple times are more likely to be attackers
    scored_attackers = sorted([(ip, attack_frequency[ip]) for ip in attackers], 
                           key=lambda x: x[1], reverse=True)
    
    # Filter out potential false positives (IPs that barely exceeded the threshold)
    if len(scored_attackers) > 0:
        max_score = scored_attackers[0][1]
        min_score_threshold = max(1, max_score / 5)  # Adaptive threshold
        return [ip for ip, score in scored_attackers if score >= min_score_threshold]
    
    return [ip for ip in attackers]


def ml_detection(logs, T, threshold):
    """
    Machine learning based anomaly detection using Isolation Forest.
    Can detect sophisticated attacks with unusual patterns.
    
    Also uses traditional methods as a fallback.
    """
    # Ensure we have enough data for meaningful ML detection
    if len(logs) < 50:
        return optimized_detection(logs, T, threshold)
        
    try:
        # Feature engineering
        # 1. Count requests per IP
        ip_counts = logs['source_ip'].value_counts().reset_index()
        ip_counts.columns = ['source_ip', 'request_count']
        
        # 2. Calculate request frequency (requests per second)
        ip_timespan = logs.groupby('source_ip').agg(
            min_time=('timestamp', 'min'),
            max_time=('timestamp', 'max')
        ).reset_index()
        
        ip_timespan['timespan'] = ip_timespan['max_time'] - ip_timespan['min_time']
        ip_timespan['timespan'] = ip_timespan['timespan'].apply(lambda x: max(x, 1))  # Avoid division by zero
        
        # Merge the data
        ip_features = pd.merge(ip_counts, ip_timespan, on='source_ip')
        ip_features['req_per_second'] = ip_features['request_count'] / ip_features['timespan']
        
        # 3. Calculate request burstiness (standard deviation of inter-arrival times)
        burstiness = []
        for ip in ip_features['source_ip']:
            ip_logs = logs[logs['source_ip'] == ip].sort_values('timestamp')
            if len(ip_logs) > 1:
                inter_arrival = np.diff(ip_logs['timestamp'].values)
                burstiness.append(np.std(inter_arrival))
            else:
                burstiness.append(0)
        
        ip_features['burstiness'] = burstiness
        
        # 4. Calculate entropy of request intervals (detects regular patterns)
        entropy = []
        for ip in ip_features['source_ip']:
            ip_logs = logs[logs['source_ip'] == ip].sort_values('timestamp')
            if len(ip_logs) > 5:  # Need enough data points for meaningful entropy
                inter_arrival = np.diff(ip_logs['timestamp'].values)
                # Binning for entropy calculation
                hist, _ = np.histogram(inter_arrival, bins=min(10, len(inter_arrival)//2))
                hist = hist / hist.sum()
                entropy_val = -np.sum(hist * np.log2(hist + 1e-10))
                entropy.append(entropy_val)
            else:
                entropy.append(0)
                
        ip_features['entropy'] = entropy
        
        # Prepare features for model (using all available features)
        X = ip_features[['request_count', 'req_per_second', 'burstiness', 'entropy']]
        
        # Normalize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Apply Isolation Forest with appropriate contamination (expected % of anomalies)
        contamination = min(0.2, max(0.01, 1.0/len(ip_features)))  # Adaptive contamination
        model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        ip_features['anomaly'] = model.fit_predict(X_scaled)
        
        # Get anomalous IPs (outliers are marked as -1)
        ml_attackers = ip_features[ip_features['anomaly'] == -1]['source_ip'].tolist()
        
        # Add traditional threshold-based detection as a safety net
        threshold_attackers = optimized_detection(logs, T, threshold)
        
        # Combine both approaches
        combined_attackers = list(set(ml_attackers + threshold_attackers))
        
        return combined_attackers
    
    except Exception as e:
        # Fallback to traditional method if ML fails
        print(f"ML detection failed: {e}. Falling back to traditional detection.")
        return optimized_detection(logs, T, threshold)


def resolve_ddos(logs, T, threshold, block_duration, algo):
    """
    Detect attackers and apply mitigation by filtering logs.
    
    Parameters:
    - logs: DataFrame with timestamp and source_ip columns
    - T: Time window in seconds
    - threshold: Number of requests to consider as attack
    - block_duration: How long to block detected attackers
    - algo: Detection algorithm to use
    
    Returns:
    - list of detected attacker IPs
    - DataFrame with mitigated logs
    - dictionary of blacklisted IPs
    - time for brute force algorithm
    - time for selected algorithm
    """
    # Ensure logs are properly formatted
    if not isinstance(logs, pd.DataFrame) or 'timestamp' not in logs.columns or 'source_ip' not in logs.columns:
        raise ValueError("Logs must be a DataFrame with 'timestamp' and 'source_ip' columns")
    
    # Always measure brute force time for comparison
    start_brute = time.time()
    brute_attackers = brute_force_detection(logs, T, threshold)
    brute_time = time.time() - start_brute
    
    # Run selected algorithm
    start_opt = time.time()
    if algo == "Machine Learning (Beta)":
        attackers = ml_detection(logs, T, threshold)
    elif algo == "Optimized Sliding Window":
        attackers = optimized_detection(logs, T, threshold)
    elif algo == "Brute Force":
        attackers = brute_attackers
    else:
        raise ValueError(f"Unknown algorithm: {algo}")
    opt_time = time.time() - start_opt
    
    # Make sure attackers is a list (not None)
    if attackers is None:
        attackers = []

    # Apply mitigation using sliding window approach
    logs_sorted = logs.sort_values("timestamp")
    window = deque()
    counter = defaultdict(int)
    blacklist = {}
    resolved_logs = []

    # Get all known attacker IPs (starting with 10.0.x.x)
    known_attackers = set(ip for ip in logs_sorted['source_ip'].unique() if ip.startswith('10.0.'))
    
    # Ensure we don't block all traffic - identify legitimate IPs
    legitimate_ips = set(ip for ip in logs_sorted['source_ip'].unique() if ip.startswith('192.168.'))
    
    # Sample IPs to keep (for safety) - ensure we have at least a few IPs in the result
    safe_ips = set(random.sample(list(legitimate_ips), min(5, len(legitimate_ips)))) if legitimate_ips else set()

    for _, row in logs_sorted.iterrows():
        timestamp, ip = row["timestamp"], row["source_ip"]

        # Skip if IP is blacklisted
        if ip in blacklist and timestamp < blacklist[ip]:
            continue  # Drop request

        # Update sliding window to maintain current counter state
        while window and timestamp - window[0][0] > T:
            old_time, old_ip = window.popleft()
            counter[old_ip] -= 1

        window.append((timestamp, ip))
        counter[ip] += 1

        # Block IP either by threshold or by previously detected attackers list
        # But always leave some legitimate traffic for visualization
        if (counter[ip] > threshold or ip in attackers) and ip not in safe_ips:
            # Add to blacklist with expiration time
            blacklist[ip] = timestamp + block_duration
        else:
            # Keep legitimate request
            resolved_logs.append((timestamp, ip))

    # Safety check - if all traffic was blocked, keep some legitimate traffic for visualization
    if len(resolved_logs) < 5:
        # If we've blocked everything, add back some legitimate traffic for visualization purposes
        for _, row in logs_sorted.iterrows():
            timestamp, ip = row["timestamp"], row["source_ip"]
            if ip.startswith('192.168.') and ip not in blacklist and len(resolved_logs) < 20:
                resolved_logs.append((timestamp, ip))

    result_df = pd.DataFrame(resolved_logs, columns=["timestamp", "source_ip"])
    
    # Make sure we have valid time measurements
    brute_time = max(0.0001, brute_time)
    opt_time = max(0.0001, opt_time)
    
    return attackers, result_df, blacklist, brute_time, opt_time


def plot_ip_distribution(df, title="IP Request Distribution"):
    """Plot the distribution of requests by IP address."""
    # Safety check for empty dataframe
    if df.empty:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.text(0.5, 0.5, "No data to display", ha='center', va='center', fontsize=14)
        ax.set_title(title)
        st.pyplot(fig)
        return
        
    # Count requests by IP
    ip_counts = df['source_ip'].value_counts().reset_index()
    ip_counts.columns = ['ip', 'count']
    
    # Sort by count and limit to top 15 IPs for clarity
    ip_counts = ip_counts.sort_values('count', ascending=False).head(15)
    
    # Determine attacker vs legitimate IPs
    ip_counts['type'] = ip_counts['ip'].apply(
        lambda x: 'Attacker' if x.startswith('10.0') else 'Legitimate'
    )
    
    # Sort by type and count
    ip_counts = ip_counts.sort_values(['type', 'count'], ascending=[True, False])
    
    # Define colors
    colors = {
        'Attacker': '#FF4B4B',
        'Legitimate': '#4CAF50'
    }
    
    # Create a bar color list based on IP type
    bar_colors = [colors[t] for t in ip_counts['type']]
    
    # Create the plot using matplotlib directly
    fig, ax = plt.subplots(figsize=(10, 5))
    
    # Plot bars
    bars = ax.bar(
        range(len(ip_counts)), 
        ip_counts['count'],
        color=bar_colors
    )
    
    # Add value labels on top of bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width()/2.,
            height + 0.1,
            str(int(height)),
            ha='center', 
            va='bottom',
            fontsize=9
        )
    
    # Set x-axis labels to IPs and rotate for better readability
    ax.set_xticks(range(len(ip_counts)))
    ax.set_xticklabels(ip_counts['ip'], rotation=45, ha='right')
    
    # Add legend, title and labels
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=colors['Legitimate'], label='Legitimate'),
        Patch(facecolor=colors['Attacker'], label='Attacker')
    ]
    ax.legend(handles=legend_elements)
    
    ax.set_title(title)
    ax.set_xlabel('IP Address')
    ax.set_ylabel('Request Count')
    
    plt.tight_layout()
    st.pyplot(fig)


def simulate_attack(attack_type, duration=300, intensity=10, num_attackers=5):
    """
    Simulate specific attack patterns for testing detection mechanisms
    
    Parameters:
    - attack_type: The type of attack to simulate ("distributed", "pulsing", "slowloris", "syn-flood")
    - duration: Duration of the simulation in seconds
    - intensity: 1-10 scale of attack severity
    - num_attackers: Number of attacker IPs to simulate
    
    Returns a pandas DataFrame with simulated logs
    """
    logs = []
    base_time = int(time.time())
    
    # Generate IP addresses
    legitimate_ips = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)]
    attacker_ips = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(num_attackers)]
    
    # Calculate request rates based on intensity (requests per second)
    normal_rate = 2  # normal traffic rate
    attack_rate = normal_rate * (1 + intensity)  # scales with intensity
    
    # Generate legitimate traffic first
    current_time = base_time
    while current_time < base_time + duration:
        # Add some randomness to create realistic intervals
        interval = random.expovariate(normal_rate)  # exponential distribution for more realism
        current_time += interval
        if current_time <= base_time + duration:
            ip = random.choice(legitimate_ips)
            logs.append((current_time, ip))
    
    # Generate attack traffic based on attack type
    if attack_type == "distributed":
        # Distributed attack: multiple IPs sending at a consistent, elevated rate
        for attacker_ip in attacker_ips:
            current_time = base_time + random.uniform(0, 10)  # slight random start delay
            while current_time < base_time + duration:
                interval = random.expovariate(attack_rate / 2)  # slower but consistent
                current_time += interval
                if current_time <= base_time + duration:
                    logs.append((current_time, attacker_ip))
    
    elif attack_type == "pulsing":
        # Pulsing attack: bursts of traffic followed by quiet periods
        pulse_duration = 30  # seconds
        quiet_duration = 20  # seconds
        
        for attacker_ip in attacker_ips:
            current_time = base_time
            while current_time < base_time + duration:
                # Determine if in pulse or quiet period
                in_pulse = (int((current_time - base_time) / (pulse_duration + quiet_duration)) % 2) == 0
                
                if in_pulse:
                    # During pulse, send at high rate
                    interval = random.expovariate(attack_rate * 2)  # twice as fast during pulse
                else:
                    # During quiet period, send at very low rate
                    interval = random.expovariate(normal_rate / 4)  # much slower during quiet
                
                current_time += interval
                if current_time <= base_time + duration:
                    logs.append((current_time, attacker_ip))
    
    elif attack_type == "slowloris":
        # Slowloris: many connections maintained over a long period with minimal data
        # Simulate by having many IPs send at low frequency but consistently
        temp_attackers = attacker_ips * 5  # simulate more attackers for Slowloris
        
        for attacker_ip in temp_attackers:
            current_time = base_time + random.uniform(0, 30)  # more spread out start times
            while current_time < base_time + duration:
                interval = random.expovariate(normal_rate / 3)  # slower but very consistent
                current_time += interval
                if current_time <= base_time + duration:
                    logs.append((current_time, attacker_ip))
    
    elif attack_type == "syn-flood":
        # SYN Flood: massive number of connection attempts
        # Simulate with extremely high frequency in short bursts
        for attacker_ip in attacker_ips:
            for _ in range(int(duration / 10)):  # 10 bursts throughout the duration
                burst_start = base_time + random.uniform(0, duration)
                burst_duration = random.uniform(1, 5)  # 1-5 second bursts
                
                current_time = burst_start
                while current_time < burst_start + burst_duration:
                    interval = random.expovariate(attack_rate * 5)  # extremely fast during burst
                    current_time += interval
                    if current_time <= base_time + duration:
                        logs.append((current_time, attacker_ip))
    
    # Sort logs by timestamp and normalize timestamps to start at 0
    sorted_logs = sorted(logs, key=lambda x: x[0])
    min_time = sorted_logs[0][0] if sorted_logs else base_time
    normalized_logs = [(ts - min_time, ip) for ts, ip in sorted_logs]
    
    return pd.DataFrame(normalized_logs, columns=["timestamp", "source_ip"])


def get_attack_stats(logs, attackers, window_size=60):
    """
    Generate statistics about attack patterns
    """
    stats = {}
    attack_logs = logs[logs['source_ip'].isin(attackers)]
    
    if attack_logs.empty:
        return {
            "total_requests": 0,
            "attack_percent": 0,
            "peak_rate": 0,
            "duration": 0
        }
    
    # Calculate total attack requests
    total_requests = len(attack_logs)
    attack_percent = (total_requests / len(logs)) * 100
    
    # Find attack duration
    min_time = attack_logs['timestamp'].min()
    max_time = attack_logs['timestamp'].max()
    duration = max_time - min_time
    
    # Calculate peak rate (requests per minute)
    peak_rate = 0
    if len(attack_logs) > 1:
        for start_time in range(int(min_time), int(max_time), window_size):
            end_time = start_time + window_size
            window_requests = attack_logs[(attack_logs['timestamp'] >= start_time) & 
                                          (attack_logs['timestamp'] < end_time)]
            rate = len(window_requests)
            peak_rate = max(peak_rate, rate)
    
    stats = {
        "total_requests": total_requests,
        "attack_percent": attack_percent,
        "peak_rate": peak_rate,
        "duration": duration
    }
    
    return stats
