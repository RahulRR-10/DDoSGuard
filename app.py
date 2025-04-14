#!/usr/bin/env python
"""
DDoSGuard - A DDoS Detection and Mitigation Tool

This application provides a user-friendly interface for simulating,
detecting, and mitigating DDoS attacks using various algorithms.

Author: Your Name
License: MIT
GitHub: https://github.com/yourusername/ddosguard
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from utils import detect_ddos, resolve_ddos, generate_fake_logs, plot_ip_distribution, simulate_attack, get_attack_stats, brute_force_detection, optimized_detection
import time

# Page configuration
st.set_page_config(
    page_title="DDoSGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Simple CSS for clean styling
st.markdown("""
<style>
    .main-header {
        font-size: 2rem;
        color: #FF4B4B;
    }
    .section-header {
        font-size: 1.5rem;
        margin-top: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Title and description
st.markdown('<p class="main-header">🛡️ DDoSGuard</p>', unsafe_allow_html=True)
st.markdown("Simple and effective DDoS Detection and Mitigation")

# Set up session state for persistence between reruns
if 'logs' not in st.session_state:
    st.session_state['logs'] = None
if 'detection_run' not in st.session_state:
    st.session_state['detection_run'] = False

# Sidebar: options
with st.sidebar:
    st.markdown("## Control Panel")
    
    # Create tabs for better organization
    option = st.radio(
        "Select Mode", 
        ["Upload Logs", "Generate Logs", "Simulate Attack"],
        help="Choose how you want to input or generate log data"
    )
    
    if st.button("Reset Application"):
        for key in st.session_state.keys():
            del st.session_state[key]
        st.experimental_rerun()

# Input methods
if option == "Upload Logs":
    st.markdown("## Upload Traffic Logs")
    
    uploaded_file = st.file_uploader("Upload CSV with 'timestamp','source_ip'", type="csv")
    if uploaded_file:
        try:
            logs = pd.read_csv(uploaded_file)
            if 'timestamp' not in logs.columns or 'source_ip' not in logs.columns:
                st.error("CSV must have 'timestamp' and 'source_ip' columns")
            else:
                st.session_state['logs'] = logs
                st.success(f"✅ Log data loaded successfully. {len(logs)} entries found.")
        except Exception as e:
            st.error(f"Error loading file: {e}")
    
elif option == "Generate Logs":
    st.markdown("## Generate Synthetic Log Data")
    
    col1, col2 = st.columns(2)
    with col1:
        num_rows = st.slider("Number of Log Entries", 500, 5000, 1000)
    with col2:
        attack_intensity = st.slider("Attack Intensity", 1, 10, 5)
    
    if st.button("Generate Log Data", type="primary"):
        with st.spinner("Generating realistic network traffic data..."):
            logs = generate_fake_logs(num_rows, attack_intensity)
            st.session_state['logs'] = logs
            
            # Count attack vs legitimate traffic
            attack_count = len(logs[logs['source_ip'].str.startswith('10.0')])
            legitimate_count = len(logs) - attack_count
            attack_percent = (attack_count / len(logs)) * 100
            
            st.success(f"✅ Generated {len(logs)} log entries with attack intensity {attack_intensity}.")
            
            # Show summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Entries", len(logs))
            with col2:
                st.metric("Attack Traffic", f"{attack_count} ({attack_percent:.1f}%)")
            with col3:
                st.metric("Legitimate Traffic", f"{legitimate_count} ({100-attack_percent:.1f}%)")
            
elif option == "Simulate Attack":
    st.markdown("## Attack Simulation")
    
    # Create columns for attack type selection
    col1, col2 = st.columns(2)
    
    with col1:
        attack_type = st.selectbox(
            "Attack Type",
            ["distributed", "pulsing", "slowloris", "syn-flood"],
            help="Select the type of DDoS attack to simulate"
        )
    
    with col2:
        # Attack configuration parameters
        duration = st.slider("Duration (seconds)", 60, 600, 180)  # Reduced default to speed up
        intensity = st.slider("Intensity", 1, 20, 10)
        num_attackers = st.slider("Number of Attacker IPs", 1, 20, 5)
    
    # Quick mode option
    quick_mode = st.checkbox("Quick Mode (faster analysis, fewer data points)", value=True)
    
    # Run the simulation
    if st.button("Run Attack Simulation", type="primary"):
        with st.spinner("Simulating attack patterns..."):
            try:
                # Use smaller log size for quick mode
                log_size_factor = 0.5 if quick_mode else 1.0
                logs = simulate_attack(attack_type, int(duration * log_size_factor), intensity, num_attackers)
                st.session_state['logs'] = logs
                
                # Display metrics
                total_requests = len(logs)
                attack_requests = logs[logs['source_ip'].str.startswith('10.0')].shape[0]
                attack_percent = (attack_requests / total_requests) * 100 if total_requests > 0 else 0
                
                # Display metrics
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Total Requests", f"{total_requests}")
                with col2:
                    st.metric("Attack Traffic", f"{attack_requests} ({attack_percent:.1f}%)")
                
                # Display traffic distribution
                st.markdown("### Traffic Distribution")
                plot_ip_distribution(logs, f"Traffic Distribution - {attack_type.title()} Attack")
                
                # Add time-based visualization to show attack pattern shape
                st.markdown("### Attack Pattern Shape")
                
                # Group data by time intervals to show pattern over time
                bin_size = max(1, int(logs['timestamp'].max() / 40))  # Create ~40 time bins
                fig, ax = plt.subplots(figsize=(10, 4))
                
                # Separate attack and legitimate traffic
                attack_logs = logs[logs['source_ip'].str.startswith('10.0')]
                legitimate_logs = logs[~logs['source_ip'].str.startswith('10.0')]
                
                # Create time bins for both
                time_bins = np.arange(0, logs['timestamp'].max() + bin_size, bin_size)
                
                # Count requests in each time bin
                attack_counts, _ = np.histogram(attack_logs['timestamp'], bins=time_bins)
                legitimate_counts, _ = np.histogram(legitimate_logs['timestamp'], bins=time_bins)
                
                # Plot
                ax.bar(range(len(attack_counts)), attack_counts, color='#FF4B4B', alpha=0.7, label='Attack Traffic')
                ax.bar(range(len(legitimate_counts)), legitimate_counts, bottom=attack_counts, color='#4CAF50', alpha=0.7, label='Legitimate Traffic')
                
                # Labels
                ax.set_xlabel("Time (binned)")
                ax.set_ylabel("Request Count")
                ax.set_title(f"Traffic Pattern Over Time - {attack_type.title()} Attack")
                ax.legend()
                
                plt.tight_layout()
                st.pyplot(fig)
                
                # Run all detection algorithms and compare effectiveness
                st.markdown("### Detection Algorithm Comparison")
                
                # Parameters for detection - use fewer combinations in quick mode
                if quick_mode:
                    T_options = [15, 45]
                    threshold_options = [10, 25]
                else:
                    T_options = [10, 30, 60]
                    threshold_options = [5, 15, 30]
                
                # Create a grid of results
                results = []
                
                # Show a progress bar for algorithm evaluation
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Calculate total iterations
                algorithms = ["Optimized Sliding Window", "Brute Force"] if quick_mode else ["Optimized Sliding Window", "Brute Force", "Machine Learning (Beta)"]
                total_iterations = len(T_options) * len(threshold_options) * len(algorithms)
                current_iteration = 0
                
                # Loop through parameters
                for T in T_options:
                    for threshold in threshold_options:
                        status_text.text(f"Evaluating with window={T}s, threshold={threshold}")
                        
                        # Run each algorithm
                        for algo in algorithms:
                            current_iteration += 1
                            progress = int(current_iteration / total_iterations * 100)
                            progress_bar.progress(progress)
                            
                            # Run detection with a timeout to prevent hanging
                            try:
                                # Run detection, stop if it takes too long (especially for brute force)
                                import threading
                                
                                result_dict = {"algorithm": algo, "attackers": [], "elapsed": 0}
                                
                                def detection_thread():
                                    attackers, elapsed = detect_ddos(logs, T, threshold, algo)
                                    result_dict["attackers"] = attackers
                                    result_dict["elapsed"] = elapsed
                                
                                # Create and start the detection thread
                                thread = threading.Thread(target=detection_thread)
                                thread.start()
                                
                                # Wait with timeout (5 seconds for quick mode, 10 seconds for full mode)
                                timeout = 3 if quick_mode else 10
                                thread.join(timeout)
                                
                                if thread.is_alive():
                                    # If thread is still running after timeout, skip this iteration
                                    status_text.text(f"Skipping {algo} (took too long)")
                                    continue
                                
                                attackers = result_dict["attackers"]
                                elapsed = result_dict["elapsed"]
                                
                                # Calculate metrics
                                actual_attackers = logs[logs['source_ip'].str.startswith('10.0')]['source_ip'].unique()
                                detected_set = set(attackers)
                                actual_set = set(actual_attackers)
                                
                                true_positives = len(detected_set.intersection(actual_set))
                                false_positives = len(detected_set - actual_set)
                                false_negatives = len(actual_set - detected_set)
                                
                                precision = true_positives / max(1, len(detected_set))
                                recall = true_positives / max(1, len(actual_set))
                                f1 = 2 * precision * recall / max(0.001, precision + recall)
                                
                                # Add to results
                                results.append({
                                    'Algorithm': algo,
                                    'Window': T,
                                    'Threshold': threshold,
                                    'Precision': precision,
                                    'Recall': recall,
                                    'F1 Score': f1,
                                    'Time (s)': elapsed,
                                    'Detected': len(attackers)
                                })
                            except Exception as e:
                                status_text.text(f"Error with {algo}: {str(e)}")
                                continue
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Check if we have results
                if not results:
                    st.error("No algorithm completed successfully. Try using Quick Mode or reducing data size.")
                else:
                    # Convert to DataFrame and display
                    results_df = pd.DataFrame(results)
                    
                    # Find best configuration for this attack type
                    best_row = results_df.loc[results_df['F1 Score'].idxmax()]
                    
                    # Display best configuration
                    st.markdown(f"#### Best Configuration for {attack_type.title()} Attack")
                    st.info(f"Algorithm: {best_row['Algorithm']} | Window: {best_row['Window']}s | Threshold: {best_row['Threshold']} | F1 Score: {best_row['F1 Score']:.2f}")
                    
                    # Let user explore all results
                    st.markdown("#### All Detection Results")
                    st.dataframe(results_df.sort_values('F1 Score', ascending=False))
                    
                    # Only create visualization if we have enough algorithms to compare
                    if len(results_df['Algorithm'].unique()) > 1:
                        # Plot F1 scores by algorithm
                        st.markdown("#### Algorithm Effectiveness")
                        
                        # Pivot table of average F1 scores by algorithm
                        algo_pivot = results_df.pivot_table(
                            index='Algorithm', 
                            values=['F1 Score', 'Precision', 'Recall'], 
                            aggfunc='mean'
                        ).reset_index()
                        
                        # Create bar chart of F1 scores
                        fig, ax = plt.subplots(figsize=(10, 4))
                        bar_colors = ['#FF4B4B', '#4CAF50', '#2196F3']
                        
                        # Plot bars for each metric
                        x = np.arange(len(algo_pivot))
                        width = 0.25
                        
                        ax.bar(x - width, algo_pivot['Precision'], width, color='#FF4B4B', label='Precision')
                        ax.bar(x, algo_pivot['Recall'], width, color='#4CAF50', label='Recall')
                        ax.bar(x + width, algo_pivot['F1 Score'], width, color='#2196F3', label='F1 Score')
                        
                        ax.set_xticks(x)
                        ax.set_xticklabels(algo_pivot['Algorithm'])
                        ax.set_ylim(0, 1.0)
                        ax.set_title(f'Algorithm Effectiveness Against {attack_type.title()} Attack')
                        ax.set_ylabel('Score')
                        ax.legend()
                        
                        plt.tight_layout()
                        st.pyplot(fig)
                
            except Exception as e:
                st.error(f"Error simulating attack: {e}")

# If logs exist in session state, display the detection panel
if st.session_state['logs'] is not None:
    logs = st.session_state['logs']
    
    st.markdown("---")
    st.markdown("## DDoS Detection & Mitigation")
    
    # Sample of logs
    if st.checkbox("Show sample data"):
        st.dataframe(logs.head(10))
    
    # Detection parameters
    st.markdown("### Detection Parameters")
    
    col1, col2 = st.columns(2)
    with col1:
        # Algorithm selection
        algo = st.selectbox(
            "Algorithm", 
            ["Optimized Sliding Window", "Brute Force", "Machine Learning (Beta)"]
        )
        
        threshold = st.slider("Threshold Requests", 5, 100, 20)
    
    with col2:
        time_window = st.slider("Time Window (seconds)", 5, 120, 30)
        block_time = st.slider("Block Duration (seconds)", 30, 300, 60)
    
    # Run detection button
    if st.button("Run Detection & Mitigation", type="primary"):
        with st.spinner("Analyzing logs..."):
            try:
                # Improved detection algorithm parameter passing
                detected, resolved_logs, blacklist, brute_time, opt_time = resolve_ddos(
                    logs, time_window, threshold, block_time, algo)
                
                st.session_state['detection_run'] = True
                
                # Results section
                st.markdown("## Detection Results")
                
                if len(detected) > 0:
                    st.success(f"✅ Attack detected! Found {len(detected)} potentially malicious IP addresses.")
                else:
                    st.info("No attack detected with current parameters.")
                
                # Results tabs
                tab1, tab2 = st.tabs(["Results", "Visualization"])
                
                with tab1:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Detected Attackers", f"{len(detected)} IPs")
                    with col2:
                        blocked_pct = ((len(logs) - len(resolved_logs)) / len(logs) * 100) if len(logs) > 0 else 0
                        st.metric("Blocked Requests", f"{len(logs) - len(resolved_logs)} ({blocked_pct:.1f}%)")
                    
                    if detected:
                        st.markdown("### Detected Attackers")
                        detected_df = pd.DataFrame(detected, columns=["IP Address"])
                        detected_df["Request Count"] = detected_df["IP Address"].apply(
                            lambda ip: len(logs[logs["source_ip"] == ip])
                        )
                        detected_df = detected_df.sort_values("Request Count", ascending=False)
                        st.dataframe(detected_df)
                
                with tab2:
                    # Traffic visualizations - before and after
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("#### Before Mitigation")
                        plot_ip_distribution(logs, "Original Traffic")
                        
                    with col2:
                        st.markdown("#### After Mitigation")
                        plot_ip_distribution(resolved_logs, "Mitigated Traffic")
                
                # Validation - check if expected attackers were found
                if 'source_ip' in logs.columns:
                    attacker_ips = logs[logs['source_ip'].str.startswith('10.0.')]['source_ip'].unique()
                    
                    if len(attacker_ips) > 0:
                        detected_set = set(detected)
                        attacker_set = set(attacker_ips)
                        
                        # Calculate detection metrics
                        true_positives = len(detected_set.intersection(attacker_set))
                        false_positives = len(detected_set - attacker_set)
                        false_negatives = len(attacker_set - detected_set)
                        
                        precision = true_positives / len(detected_set) if len(detected_set) > 0 else 0
                        recall = true_positives / len(attacker_set) if len(attacker_set) > 0 else 0
                        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                        
                        st.markdown("### Detection Accuracy")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Precision", f"{precision:.2f}")
                        with col2:
                            st.metric("Recall", f"{recall:.2f}")
                        with col3:
                            st.metric("F1 Score", f"{f1_score:.2f}")
                        
                        if precision < 0.7 or recall < 0.7:
                            st.warning("Detection needs improvement. Try adjusting parameters.")
                
            except Exception as e:
                st.error(f"Error in detection: {e}")

# Function to compare algorithms
def compare_algorithms(logs, T, threshold):
    # Measure execution time for Brute Force
    start_brute = time.time()
    brute_attackers = brute_force_detection(logs, T, threshold)
    brute_time = time.time() - start_brute

    # Measure execution time for Optimized Sliding Window
    start_opt = time.time()
    opt_attackers = optimized_detection(logs, T, threshold)
    opt_time = time.time() - start_opt

    return brute_time, opt_time, len(brute_attackers), len(opt_attackers)

# Streamlit UI
st.title("DDoS Detection Comparison")

# User inputs for parameters
T = st.slider("Time Window (seconds)", 5, 120, 30, key="time_window_slider")
threshold = st.slider("Threshold Requests", 1, 100, 20, key="threshold_slider")

# Button to run comparison
if st.button("Compare Algorithms"):
    # Check if logs are loaded
    if st.session_state['logs'] is None:
        st.error("Please load or generate logs before comparing algorithms.")
    else:
        logs = st.session_state['logs']
        brute_time, opt_time, brute_count, opt_count = compare_algorithms(logs, T, threshold)

        # Display results
        st.write(f"Brute Force Detected Attackers: {brute_count} in {brute_time:.2f} seconds")
        st.write(f"Optimized Sliding Window Detected Attackers: {opt_count} in {opt_time:.2f} seconds")

        # Plotting the results
        labels = ['Brute Force', 'Optimized Sliding Window']
        times = [brute_time, opt_time]
        
        fig, ax = plt.subplots()
        ax.bar(labels, times, color=['red', 'blue'])
        ax.set_ylabel('Execution Time (seconds)')
        ax.set_title('Algorithm Execution Time Comparison')
        st.pyplot(fig)

        # Display Big O Notation
        st.write("### Time Complexity:")
        st.write("- Brute Force: O(n²) - Compares every log entry with every other entry.")
        st.write("- Optimized Sliding Window: O(n) - Efficiently tracks requests within the time window.")
