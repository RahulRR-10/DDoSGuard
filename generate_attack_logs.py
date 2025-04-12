#!/usr/bin/env python
import pandas as pd
import argparse
from utils import simulate_attack

def main():
    parser = argparse.ArgumentParser(description="Generate DDoS attack log files for testing.")
    parser.add_argument("--output", default="attack_logs.csv", help="Output CSV file path")
    parser.add_argument("--type", default="distributed", 
                        choices=["distributed", "pulsing", "slowloris", "syn-flood"],
                        help="Type of attack to simulate")
    parser.add_argument("--duration", type=int, default=300, 
                        help="Duration of attack simulation in seconds")
    parser.add_argument("--intensity", type=int, default=10, 
                        help="Attack intensity (1-20)")
    parser.add_argument("--attackers", type=int, default=5,
                        help="Number of attacker IPs")

    args = parser.parse_args()
    
    print(f"Generating {args.type} attack logs...")
    logs = simulate_attack(
        attack_type=args.type,
        duration=args.duration,
        intensity=args.intensity,
        num_attackers=args.attackers
    )
    
    logs.to_csv(args.output, index=False)
    print(f"Generated {len(logs)} log entries.")
    print(f"Attack logs saved to {args.output}")
    
    # Display a summary
    attacker_count = logs['source_ip'].str.startswith('10.0').sum()
    legitimate_count = len(logs) - attacker_count
    
    print("\nSummary:")
    print(f"Total requests: {len(logs)}")
    print(f"Attack requests: {attacker_count} ({attacker_count/len(logs)*100:.1f}%)")
    print(f"Legitimate requests: {legitimate_count} ({legitimate_count/len(logs)*100:.1f}%)")
    
    # Show a sample of the data
    print("\nSample of the generated data:")
    print(logs.head(10))

if __name__ == "__main__":
    main() 