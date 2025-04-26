import numpy as np
import logging
from collections import deque
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from models import AnomalyLog
from db import db

class AnomalyDetector:
    """
    Early Anomaly Detection Engine using a combination of methods:
    - Entropy thresholding
    - Burst detection
    - Machine Learning anomaly detection (Isolation Forest)
    """
    
    def __init__(self, entropy_threshold=2.0, burst_threshold=3.0):
        """
        Initialize the Anomaly Detector.
        
        Args:
            entropy_threshold (float): Threshold for entropy-based detection
            burst_threshold (float): Threshold for burst detection
        """
        self.logger = logging.getLogger(__name__)
        self.entropy_threshold = entropy_threshold
        self.burst_threshold = burst_threshold
        
        # Initialize ML model
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Expect about 5% of traffic to be anomalous
            random_state=42
        )
        
        # Storage for anomaly data
        self.anomaly_history = deque(maxlen=1000)
        self.feature_history = deque(maxlen=100)  # Last 100 data points for ML
        self.model_trained = False
        
        self.logger.info("Anomaly Detector initialized with entropy threshold: %.2f, burst threshold: %.2f", 
                        entropy_threshold, burst_threshold)
    
    def detect_anomalies(self, metrics):
        """
        Detect potential DDoS attacks using multiple detection methods.
        
        Args:
            metrics (dict): Current traffic metrics
            
        Returns:
            float: Anomaly score (0.0 to 1.0, where higher means more anomalous)
        """
        if not metrics:
            return 0.0
        
        # Extract features
        features = [
            metrics.get('requests_per_second', 0),
            metrics.get('unique_ips', 0),
            metrics.get('entropy_value', 0),
            metrics.get('burst_score', 0)
        ]
        
        # Add to feature history
        self.feature_history.append(features)
        
        # Calculate anomaly scores from different methods
        entropy_score = self._entropy_based_detection(metrics)
        burst_score = self._burst_detection(metrics)
        ml_score = self._ml_based_detection()
        
        # Combine scores (weighted average)
        combined_score = 0.4 * entropy_score + 0.3 * burst_score + 0.3 * ml_score
        
        # Create anomaly record
        anomaly_record = {
            'timestamp': datetime.utcnow(),
            'anomaly_score': combined_score,
            'entropy_value': metrics.get('entropy_value', 0),
            'burst_score': metrics.get('burst_score', 0),
            'unique_ips': metrics.get('unique_ips', 0),
            'total_requests': metrics.get('total_requests', 0)
        }
        
        # Add to history
        self.anomaly_history.append(anomaly_record)
        
        # Log to database if score is significant (to avoid filling the database)
        if combined_score > 0.3:
            self._log_anomaly(anomaly_record)
        
        return combined_score
    
    def _entropy_based_detection(self, metrics):
        """
        Detect anomalies based on entropy values.
        
        Args:
            metrics (dict): Current traffic metrics
            
        Returns:
            float: Entropy-based anomaly score (0.0 to 1.0)
        """
        entropy_value = metrics.get('entropy_value', 0)
        
        # Low entropy can indicate DDoS (many requests from few sources)
        # High entropy can indicate distributed attacks (many sources)
        if entropy_value < 0.5:
            # Low entropy anomaly (concentrated sources)
            score = 1.0 - entropy_value
        elif entropy_value > self.entropy_threshold:
            # High entropy anomaly (too distributed)
            score = (entropy_value - self.entropy_threshold) / (4.0 - self.entropy_threshold)
            score = min(score, 1.0)
        else:
            # Normal range
            score = 0.0
        
        return score
    
    def _burst_detection(self, metrics):
        """
        Detect anomalies based on traffic burstiness.
        
        Args:
            metrics (dict): Current traffic metrics
            
        Returns:
            float: Burst-based anomaly score (0.0 to 1.0)
        """
        burst_score = metrics.get('burst_score', 0)
        
        if burst_score > self.burst_threshold:
            # Normalize score between 0 and 1
            score = (burst_score - self.burst_threshold) / (10.0 - self.burst_threshold)
            score = min(score, 1.0)
        else:
            score = 0.0
        
        return score
    
    def _ml_based_detection(self):
        """
        Detect anomalies using Isolation Forest algorithm.
        
        Returns:
            float: ML-based anomaly score (0.0 to 1.0)
        """
        if len(self.feature_history) < 50:
            # Not enough data to train the model
            return 0.0
        
        try:
            # Convert feature history to numpy array
            X = np.array(list(self.feature_history))
            
            # Train the model if not already trained
            if not self.model_trained or len(self.feature_history) % 50 == 0:
                self.isolation_forest.fit(X)
                self.model_trained = True
                self.logger.info("Isolation Forest model trained/updated")
            
            # Get anomaly score for the most recent data point
            # Isolation Forest returns -1 for anomalies and 1 for normal points
            # We need to convert to a 0 to 1 score where 1 is anomalous
            scores = self.isolation_forest.decision_function(X[-1:])
            # Convert from decision function to normalized score (0 to 1, where 1 is anomalous)
            normalized_score = 1.0 - (scores[0] + 0.5) / 1.5
            normalized_score = max(0.0, min(1.0, normalized_score))
            
            return normalized_score
        
        except Exception as e:
            self.logger.error(f"Error in ML-based detection: {str(e)}")
            return 0.0
    
    def _log_anomaly(self, anomaly_record):
        """
        Log an anomaly to the database.
        
        Args:
            anomaly_record (dict): Anomaly data
        """
        try:
            # Convert numpy types to native Python types to avoid SQL errors
            anomaly_log = AnomalyLog(
                anomaly_score=float(anomaly_record['anomaly_score']),
                entropy_value=float(anomaly_record['entropy_value']),
                burst_score=float(anomaly_record['burst_score']),
                unique_ips=int(anomaly_record['unique_ips']),
                total_requests=int(anomaly_record['total_requests'])
            )
            db.session.add(anomaly_log)
            db.session.commit()
        except Exception as e:
            self.logger.error(f"Error logging anomaly: {str(e)}")
            db.session.rollback()
    
    def reset(self):
        """
        Reset the anomaly detector state to start fresh.
        This is used when resetting after a simulation ends.
        """
        self.logger.info("Resetting anomaly detector state")
        
        # Clear histories
        self.anomaly_history.clear()
        self.feature_history.clear()
        
        # Reset ML model
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self.model_trained = False
    
    def get_anomalies(self, minutes=30):
        """
        Get historical anomaly records for the specified time period.
        
        Args:
            minutes (int): Number of minutes of history to return
            
        Returns:
            list: List of anomaly dictionaries
        """
        # Convert deque to list for serialization
        history = list(self.anomaly_history)
        
        # Filter by time if we have timestamps
        if history and 'timestamp' in history[0]:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            history = [a for a in history if a['timestamp'] > cutoff_time]
        
        return history
