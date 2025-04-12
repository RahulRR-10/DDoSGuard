#!/usr/bin/env python
"""
Test script to verify all detection algorithms are working correctly.
This ensures proper detection of various attack types.
"""

import pandas as pd
import time
from utils import (
    brute_force_detection,
    optimized_detection,
    ml_detection,
    simulate_attack
)

def test_algorithm(algorithm_name, algorithm_func, logs, time_window, threshold):
    """Test a detection algorithm and report results"""
    start_time = time.time()
    attackers = algorithm_func(logs, time_window, threshold)
    execution_time = time.time() - start_time
    
    # Check if known attackers (10.0.0.x) were detected
    actual_attackers = logs[logs['source_ip'].str.startswith('10.0.')]['source_ip'].unique()
    detected_set = set(attackers)
    actual_set = set(actual_attackers)
    
    # Calculate metrics
    true_positives = len(detected_set.intersection(actual_set))
    false_positives = len(detected_set - actual_set)
    false_negatives = len(actual_set - detected_set)
    
    precision = true_positives / len(detected_set) if len(detected_set) > 0 else 0
    recall = true_positives / len(actual_set) if len(actual_set) > 0 else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n===== {algorithm_name} =====")
    print(f"Execution time: {execution_time:.5f} seconds")
    print(f"Detected {len(attackers)} attackers out of {len(actual_attackers)} actual attackers")
    print(f"Precision: {precision:.2f}, Recall: {recall:.2f}, F1 Score: {f1_score:.2f}")
    print(f"True Positives: {true_positives}, False Positives: {false_positives}, False Negatives: {false_negatives}")
    
    return attackers, execution_time, precision, recall

def main():
    # Test parameters
    print("Testing all DDoS detection algorithms...")
    
    # Test different attack types
    attack_types = ['distributed', 'pulsing', 'slowloris', 'syn-flood']
    
    for attack_type in attack_types:
        print(f"\n\n======= Testing {attack_type.upper()} attack =======")
        # Generate test data
        logs = simulate_attack(
            attack_type=attack_type,
            duration=120,
            intensity=8,
            num_attackers=4
        )
        
        # Basic stats
        total_requests = len(logs)
        attacker_requests = logs[logs['source_ip'].str.startswith('10.0.')].shape[0]
        attack_percentage = attacker_requests / total_requests * 100
        
        print(f"Generated {total_requests} log entries ({attack_percentage:.1f}% attack traffic)")
        
        # Test each algorithm with different thresholds
        thresholds = [5, 10, 15]
        time_window = 30
        
        for threshold in thresholds:
            print(f"\n--- Threshold: {threshold}, Time Window: {time_window}s ---")
            
            # Test brute force algorithm
            brute_attackers, brute_time, brute_precision, brute_recall = test_algorithm(
                "Brute Force Detection", brute_force_detection, logs, time_window, threshold
            )
            
            # Test optimized algorithm
            opt_attackers, opt_time, opt_precision, opt_recall = test_algorithm(
                "Optimized Detection", optimized_detection, logs, time_window, threshold
            )
            
            # Test ML algorithm
            ml_attackers, ml_time, ml_precision, ml_recall = test_algorithm(
                "Machine Learning Detection", ml_detection, logs, time_window, threshold
            )
            
            # Calculate speedups
            opt_speedup = brute_time / opt_time if opt_time > 0 else 0
            ml_speedup = brute_time / ml_time if ml_time > 0 else 0
            
            print(f"\n--- Performance Comparison ---")
            print(f"Optimized is {opt_speedup:.1f}x faster than Brute Force")
            print(f"Machine Learning is {ml_speedup:.1f}x faster than Brute Force")
            
            # Compare detection quality
            print(f"\n--- Detection Quality ---")
            print(f"{'Algorithm':<25} {'Precision':<10} {'Recall':<10}")
            print(f"{'-'*25} {'-'*10} {'-'*10}")
            print(f"{'Brute Force':<25} {brute_precision:.2f}{' ':>4} {brute_recall:.2f}{' ':>4}")
            print(f"{'Optimized Sliding Window':<25} {opt_precision:.2f}{' ':>4} {opt_recall:.2f}{' ':>4}")
            print(f"{'Machine Learning':<25} {ml_precision:.2f}{' ':>4} {ml_recall:.2f}{' ':>4}")

if __name__ == "__main__":
    main() 