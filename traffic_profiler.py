import numpy as np
import pandas as pd
import time
import logging
from collections import deque, Counter
from datetime import datetime, timedelta
from scipy.stats import entropy
from models import TrafficLog, TrafficMetrics, BaselineProfile
from app import db

class TrafficProfiler:
    """
    Traffic Profiler component that continuously monitors incoming network traffic
    and extracts various metrics for analysis.
    """
    
    def __init__(self, window_size=60):
        """
        Initialize the Traffic Profiler with a default window size of 60 seconds.
        
        Args:
            window_size (int): Size of the sliding window in seconds
        """
        self.logger = logging.getLogger(__name__)
        self.window_size = window_size
        
        # Sliding window to store recent requests
        self.request_window = deque()
        
        # Metrics storage - use list instead of deque for slicing operations
        self.metrics_history = []  # Store up to 1000 data points
        self.max_history = 1000
        
        # Counter for real-time metrics
        self.ip_counter = Counter()
        self.request_count = 0
        self.last_update_time = time.time()
        
        # Baseline metrics
        self.baseline = None
        self.load_or_create_baseline()
        
        self.logger.info("Traffic Profiler initialized with window size of %d seconds", window_size)
    
    def process_request(self, ip_address, path="/", method="GET"):
        """
        Process an incoming request and update metrics.
        
        Args:
            ip_address (str): The source IP address
            path (str): The requested path
            method (str): The HTTP method used
        """
        current_time = time.time()
        
        # Add to request window
        self.request_window.append({
            'ip_address': ip_address,
            'timestamp': current_time,
            'path': path,
            'method': method
        })
        
        # Update counters
        self.ip_counter[ip_address] += 1
        self.request_count += 1
        
        # Remove old requests from window
        self._clean_window(current_time)
        
        # Log request to database (throttled to avoid DB overload)
        if self.request_count % 10 == 0:  # Log every 10th request
            self._log_request(ip_address, path, method)
        
        # Update metrics if enough time has passed
        if current_time - self.last_update_time >= 1.0:  # Update metrics every second
            self._update_metrics()
            self.last_update_time = current_time
    
    def _clean_window(self, current_time):
        """
        Remove requests older than window_size from the sliding window.
        
        Args:
            current_time (float): Current timestamp
        """
        cutoff_time = current_time - self.window_size
        
        while self.request_window and self.request_window[0]['timestamp'] < cutoff_time:
            old_request = self.request_window.popleft()
            self.ip_counter[old_request['ip_address']] -= 1
            
            # Remove IP from counter if count reaches 0
            if self.ip_counter[old_request['ip_address']] <= 0:
                del self.ip_counter[old_request['ip_address']]
    
    def _log_request(self, ip_address, path, method):
        """
        Log a request to the database.
        
        Args:
            ip_address (str): The source IP address
            path (str): The requested path
            method (str): The HTTP method used
        """
        try:
            log_entry = TrafficLog(
                ip_address=ip_address,
                path=path,
                method=method
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            self.logger.error(f"Error logging request: {str(e)}")
            db.session.rollback()
    
    def _update_metrics(self):
        """Update and store traffic metrics based on the current window."""
        if not self.request_window:
            return
        
        # Calculate metrics
        window_duration = self.window_size
        total_requests = len(self.request_window)
        requests_per_second = total_requests / window_duration if window_duration > 0 else 0
        unique_ips = len(self.ip_counter)
        
        # Calculate entropy of source IP distribution
        ip_counts = list(self.ip_counter.values())
        if sum(ip_counts) > 0:
            ip_probabilities = [count / total_requests for count in ip_counts]
            ip_entropy = entropy(ip_probabilities)
        else:
            ip_entropy = 0
        
        # Calculate burstiness score (variance in requests per second)
        if len(self.metrics_history) > 1:
            recent_rps = [m['requests_per_second'] for m in self.metrics_history[-10:]]
            burst_score = np.std(recent_rps) / (np.mean(recent_rps) if np.mean(recent_rps) > 0 else 1)
        else:
            burst_score = 0
        
        # Create metrics object
        metrics = {
            'timestamp': datetime.utcnow(),
            'requests_per_second': requests_per_second,
            'unique_ips': unique_ips,
            'entropy_value': ip_entropy,
            'burst_score': burst_score,
            'total_requests': total_requests
        }
        
        # Add to history
        self.metrics_history.append(metrics)
        
        # Trim history if it exceeds max length
        if len(self.metrics_history) > self.max_history:
            self.metrics_history = self.metrics_history[-self.max_history:]
        
        # Store in database (throttled to reduce DB writes)
        if len(self.metrics_history) % 5 == 0:  # Store every 5th metric update
            try:
                metrics_entry = TrafficMetrics(
                    requests_per_second=requests_per_second,
                    unique_ips=unique_ips,
                    entropy_value=ip_entropy,
                    burst_score=burst_score
                )
                db.session.add(metrics_entry)
                db.session.commit()
            except Exception as e:
                self.logger.error(f"Error storing metrics: {str(e)}")
                db.session.rollback()
        
        # Update baseline if needed
        if self.baseline is None or len(self.metrics_history) % 1000 == 0:
            self.update_baseline()
    
    def get_current_metrics(self):
        """
        Get the most recent traffic metrics.
        
        Returns:
            dict: Current traffic metrics
        """
        if not self.metrics_history:
            return {
                'timestamp': datetime.utcnow(),
                'requests_per_second': 0,
                'unique_ips': 0,
                'entropy_value': 0,
                'burst_score': 0,
                'total_requests': 0
            }
        
        return self.metrics_history[-1]
    
    def get_traffic_history(self, minutes=30):
        """
        Get historical traffic metrics for the specified time period.
        
        Args:
            minutes (int): Number of minutes of history to return
            
        Returns:
            list: List of traffic metric dictionaries
        """
        # Convert deque to list for serialization
        history = list(self.metrics_history)
        
        # Filter by time if we have timestamps
        if history and 'timestamp' in history[0]:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            history = [m for m in history if m['timestamp'] > cutoff_time]
        
        return history
    
    def update_baseline(self):
        """Update the baseline profile based on recent traffic patterns."""
        if len(self.metrics_history) < 50:
            self.logger.info("Not enough data to establish a baseline profile")
            return
        
        # Convert to DataFrame for easier analysis
        metrics_df = pd.DataFrame(list(self.metrics_history))
        
        # Calculate baseline metrics
        avg_rps = metrics_df['requests_per_second'].mean()
        avg_unique_ips = metrics_df['unique_ips'].mean()
        avg_entropy = metrics_df['entropy_value'].mean()
        std_rps = metrics_df['requests_per_second'].std()
        std_unique_ips = metrics_df['unique_ips'].std()
        std_entropy = metrics_df['entropy_value'].std()
        
        # Create new baseline
        try:
            # Deactivate old baseline
            BaselineProfile.query.update({'is_active': False})
            
            # Create new baseline
            new_baseline = BaselineProfile(
                avg_requests_per_second=avg_rps,
                avg_unique_ips=avg_unique_ips,
                avg_entropy=avg_entropy,
                std_requests_per_second=std_rps,
                std_unique_ips=std_unique_ips,
                std_entropy=std_entropy,
                is_active=True
            )
            
            db.session.add(new_baseline)
            db.session.commit()
            
            # Update in-memory baseline
            self.baseline = {
                'avg_requests_per_second': avg_rps,
                'avg_unique_ips': avg_unique_ips,
                'avg_entropy': avg_entropy,
                'std_requests_per_second': std_rps,
                'std_unique_ips': std_unique_ips,
                'std_entropy': std_entropy
            }
            
            self.logger.info("Updated baseline profile")
        except Exception as e:
            self.logger.error(f"Error updating baseline: {str(e)}")
            db.session.rollback()
    
    def load_or_create_baseline(self):
        """Load the most recent baseline profile from the database or create a default one."""
        # Create a default baseline first
        self.baseline = {
            'avg_requests_per_second': 1.0,
            'avg_unique_ips': 5.0,
            'avg_entropy': 1.0,
            'std_requests_per_second': 0.5,
            'std_unique_ips': 2.0,
            'std_entropy': 0.5
        }
        self.logger.info("Created default baseline profile")
            
        # We'll try to load from database on the first API call
        # when the Flask context is available
