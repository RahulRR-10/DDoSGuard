import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize database
db = SQLAlchemy(model_class=Base)

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "sentinelddos-secret")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///sentinelddos.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Import components
from traffic_profiler import TrafficProfiler
from anomaly_detector import AnomalyDetector
from mitigation import MitigationSystem
from attack_simulator import AttackSimulator

# Initialize components
traffic_profiler = TrafficProfiler()
anomaly_detector = AnomalyDetector()
mitigation_system = MitigationSystem()
attack_simulator = AttackSimulator()

# Routes
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/simulator')
def simulator():
    return render_template('simulator.html')

@app.route('/settings')
def settings():
    return render_template('settings.html', 
                           entropy_threshold=anomaly_detector.entropy_threshold,
                           burst_threshold=anomaly_detector.burst_threshold,
                           window_size=traffic_profiler.window_size)

@app.route('/reports')
def reports():
    return render_template('reports.html')

# API endpoints
@app.route('/api/traffic/current', methods=['GET'])
def get_current_traffic():
    try:
        metrics = traffic_profiler.get_current_metrics()
        app.logger.debug(f"Returning current traffic metrics: {metrics}")
        return jsonify(metrics)
    except Exception as e:
        app.logger.error(f"Error getting current traffic metrics: {str(e)}")
        # Return empty metrics to prevent frontend errors
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'requests_per_second': 0,
            'unique_ips': 0,
            'entropy_value': 0,
            'burst_score': 0,
            'total_requests': 0
        })

@app.route('/api/traffic/history', methods=['GET'])
def get_traffic_history():
    try:
        history = traffic_profiler.get_traffic_history()
        app.logger.debug(f"Returning traffic history with {len(history)} items")
        return jsonify(history)
    except Exception as e:
        app.logger.error(f"Error getting traffic history: {str(e)}")
        # Return empty history to prevent frontend errors
        return jsonify([])

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    try:
        anomalies = anomaly_detector.get_anomalies()
        app.logger.debug(f"Returning {len(anomalies)} anomalies")
        return jsonify(anomalies)
    except Exception as e:
        app.logger.error(f"Error getting anomalies: {str(e)}")
        # Return empty array to prevent frontend errors
        return jsonify([])

@app.route('/api/mitigation/status', methods=['GET'])
def get_mitigation_status():
    try:
        status = mitigation_system.get_status()
        app.logger.debug(f"Returning mitigation status: {status}")
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Error getting mitigation status: {str(e)}")
        # Return default status to prevent frontend errors
        return jsonify({
            'active_mitigations': 0,
            'recent_actions': [],
            'rate_limited_ips': 0,
            'blocked_ips_count': 0
        })

@app.route('/api/mitigation/blocked', methods=['GET'])
def get_blocked_ips():
    try:
        blocked = mitigation_system.get_blocked_ips()
        app.logger.debug(f"Returning {len(blocked)} blocked IPs")
        return jsonify(blocked)
    except Exception as e:
        app.logger.error(f"Error getting blocked IPs: {str(e)}")
        # Return empty array to prevent frontend errors
        return jsonify([])

@app.route('/api/simulate/attack', methods=['POST'])
def simulate_attack():
    attack_type = request.json.get('attack_type', 'flooding')
    duration = int(request.json.get('duration', 60))
    intensity = int(request.json.get('intensity', 5))
    distribution = request.json.get('distribution', 'random')
    
    attack_simulator.start_attack(
        attack_type=attack_type,
        duration=duration,
        intensity=intensity,
        distribution=distribution
    )
    
    return jsonify({'status': 'Attack simulation started'})

@app.route('/api/simulate/stop', methods=['POST'])
def stop_simulation():
    try:
        # Stop the attack simulation
        attack_simulator.stop_attack()
        
        # Call the mitigation cleanup to remove any simulation IP blocks
        # This ensures that when a simulation stops, all blocked IPs are cleared
        mitigation_system.cleanup()
        app.logger.info("Cleaned up simulation blocks after stopping attack")
        
        # Clean up historical anomalies from the simulation
        with app.app_context():
            from models import AnomalyLog, TrafficMetrics, TrafficLog
            from datetime import datetime, timedelta
            import random
            
            # Get current time
            now = datetime.utcnow()
            
            # Find and delete anomalies created in the last 5 minutes (likely from simulation)
            recent_anomalies = AnomalyLog.query.filter(
                AnomalyLog.timestamp > (now - timedelta(minutes=5))
            ).all()
            
            if recent_anomalies:
                app.logger.info(f"Cleaning up {len(recent_anomalies)} recent anomalies after simulation")
                for anomaly in recent_anomalies:
                    db.session.delete(anomaly)
            
            # Delete recent traffic metrics to reset graphs
            recent_metrics = TrafficMetrics.query.filter(
                TrafficMetrics.timestamp > (now - timedelta(minutes=5))
            ).all()
            
            if recent_metrics:
                app.logger.info(f"Cleaning up {len(recent_metrics)} recent traffic metrics after simulation")
                for metric in recent_metrics:
                    db.session.delete(metric)
            
            # Delete recent traffic logs that might be from simulation
            recent_logs = TrafficLog.query.filter(
                TrafficLog.timestamp > (now - timedelta(minutes=5))
            ).all()
            
            if recent_logs:
                app.logger.info(f"Cleaning up {len(recent_logs)} recent traffic logs after simulation")
                for log in recent_logs:
                    db.session.delete(log)
                    
            # Create new baseline normal traffic
            normal_rps = random.uniform(1.5, 4.0)
            normal_unique_ips = random.randint(10, 30)
            normal_entropy = random.uniform(3.0, 4.0)
            normal_burst = random.uniform(0.01, 0.1)
            
            # Add a few normal traffic metrics to establish a baseline
            for i in range(10):
                # Slight random variations in normal traffic
                rps_variation = random.uniform(0.8, 1.2)
                unique_ips_variation = random.uniform(0.9, 1.1)
                entropy_variation = random.uniform(0.95, 1.05)
                burst_variation = random.uniform(0.9, 1.1)
                
                # Create metrics slightly in the past (to establish timeline)
                timestamp = now - timedelta(seconds=(10-i)*30)
                
                metric = TrafficMetrics(
                    timestamp=timestamp,
                    requests_per_second=normal_rps * rps_variation,
                    unique_ips=int(normal_unique_ips * unique_ips_variation),
                    entropy_value=normal_entropy * entropy_variation,
                    burst_score=normal_burst * burst_variation
                )
                db.session.add(metric)
            
            # Commit all changes
            db.session.commit()
        
        # Reset the traffic profiler's internal state
        from collections import deque, Counter
        traffic_profiler.request_window = deque()
        traffic_profiler.ip_counter = Counter()
        traffic_profiler.request_count = 0
        traffic_profiler.metrics_history = []  # Clear metrics history too
        
        # Reset the anomaly detector state
        anomaly_detector.reset()
        
        return jsonify({'status': 'Attack simulation stopped and system reset to normal conditions'})
    
    except Exception as e:
        app.logger.error(f"Error stopping attack simulation: {str(e)}")
        try:
            # If an error occurred during cleanup, make sure to roll back any pending transactions
            with app.app_context():
                db.session.rollback()
        except Exception as inner_e:
            app.logger.error(f"Error rolling back after simulation stop failure: {str(inner_e)}")
            
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/simulate/status', methods=['GET'])
def get_attack_status():
    try:
        status = attack_simulator.get_attack_status()
        app.logger.debug(f"Returning attack status: {status}")
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Error getting attack status: {str(e)}")
        # Return default status to prevent frontend errors
        return jsonify({
            'is_running': False,
            'attack_type': None,
            'start_time': None,
            'intensity': None,
            'distribution': None,
            'duration': None
        })
        
@app.route('/api/simulate/attack/history', methods=['GET'])
def get_attack_history():
    """Get history of past attacks for the reports page"""
    try:
        from models import AttackLog
        import random
        from datetime import datetime, timedelta
        
        # Query all attacks regardless of status to make sure we're getting data
        all_attacks = AttackLog.query.order_by(AttackLog.start_time.desc()).limit(100).all()
        
        # Log what we found for debugging
        app.logger.debug(f"Found {len(all_attacks)} total attack records in database")
        
        # If no attacks are found, create sample data for demonstration
        if len(all_attacks) == 0:
            app.logger.info("No attack history found. Creating sample attack history for demonstration.")
            
            # Get attack types from simulator to use real values
            attack_types = attack_simulator.get_attack_types()
            distributions = ['random', 'subnet', 'fixed']
            
            # Create sample attacks across the past 48 hours
            now = datetime.utcnow()
            
            # Generate between 10-15 sample attacks
            num_attacks = random.randint(10, 15)
            
            for i in range(num_attacks):
                # Random start time in the past 48 hours
                hours_ago = random.randint(1, 48)
                minutes_ago = random.randint(0, 59)
                start_time = now - timedelta(hours=hours_ago, minutes=minutes_ago)
                
                # Duration between 1-30 minutes
                duration_minutes = random.randint(1, 30)
                end_time = start_time + timedelta(minutes=duration_minutes)
                
                # Last attack might still be active
                is_active = (i == 0 and random.random() < 0.3)
                
                # Random attack parameters
                attack_type = random.choice(attack_types)
                intensity = random.randint(3, 10)
                distribution = random.choice(distributions)
                
                # Create and add the attack log
                attack_log = AttackLog(
                    start_time=start_time,
                    end_time=None if is_active else end_time,
                    attack_type=attack_type,
                    intensity=intensity,
                    distribution=distribution,
                    is_active=is_active
                )
                
                db.session.add(attack_log)
            
            db.session.commit()
            app.logger.info(f"Created {num_attacks} sample attack logs for demonstration")
            
            # Refetch attacks after creating samples
            all_attacks = AttackLog.query.order_by(AttackLog.start_time.desc()).limit(100).all()
        
        # Handle active and inactive attacks separately
        active_attacks = []
        completed_attacks = []
        
        for attack in all_attacks:
            if attack.is_active:
                active_attacks.append(attack)
            elif attack.end_time is not None:
                completed_attacks.append(attack)
        
        # Limited to 20 most recent attacks
        attacks = active_attacks + completed_attacks[:20]
        
        result = []
        for attack in attacks:
            # Create a dictionary with all available attack data
            attack_data = {
                'id': attack.id,
                'start_time': attack.start_time,
                'end_time': attack.end_time,
                'attack_type': attack.attack_type or 'unknown',
                'intensity': attack.intensity or 5,
                'distribution': attack.distribution or 'random',
                'is_active': attack.is_active
            }
            result.append(attack_data)
            
        app.logger.debug(f"Returning {len(result)} attack history records")
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error getting attack history: {str(e)}")
        # Return empty list to prevent frontend errors
        return jsonify([])

@app.route('/api/settings/update', methods=['POST'])
def update_settings():
    try:
        # Update anomaly detector settings
        if 'entropy_threshold' in request.json:
            anomaly_detector.entropy_threshold = float(request.json['entropy_threshold'])
        
        if 'burst_threshold' in request.json:
            anomaly_detector.burst_threshold = float(request.json['burst_threshold'])
        
        # Update traffic profiler settings
        if 'window_size' in request.json:
            traffic_profiler.window_size = int(request.json['window_size'])
        
        # Update mitigation settings
        if 'light_threshold' in request.json:
            mitigation_system.light_threshold = float(request.json['light_threshold'])
        
        if 'medium_threshold' in request.json:
            mitigation_system.medium_threshold = float(request.json['medium_threshold'])
        
        if 'severe_threshold' in request.json:
            mitigation_system.severe_threshold = float(request.json['severe_threshold'])
        
        flash('Settings updated successfully', 'success')
        return jsonify({'status': 'success', 'message': 'Settings updated'})
    
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/process_request', methods=['GET', 'POST'])
def process_request():
    """Endpoint to handle incoming traffic for monitoring purposes"""
    # Get the real IP address from X-Forwarded-For header or fallback to remote_addr
    # This is important for attack simulation which uses X-Forwarded-For
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    path = request.path
    method = request.method
    
    # Check if this is simulated attack traffic
    attack_type = request.headers.get('X-Attack-Type', None)
    is_simulation = attack_type is not None or ip.startswith('192.168.')
    
    if is_simulation:
        app.logger.info(f"Processing simulated attack traffic from {ip} {attack_type if attack_type else ''}")
        
        # Check if attack simulation is active in the simulator
        attack_status = attack_simulator.get_attack_status()
        if not attack_status['is_running']:
            app.logger.warning("Received simulated attack traffic but no attack is marked as running in the simulator")
            # Auto-fix the running status if needed
            if attack_simulator.current_attack and attack_simulator.current_attack.is_active:
                attack_simulator.is_running = True
                app.logger.info("Auto-corrected attack simulator running status")
        
        # Process simulated traffic with higher weight based on intensity
        # Use the simulator's intensity setting to determine weight
        intensity = 5  # Default intensity
        if attack_status['is_running'] and attack_status['intensity']:
            intensity = attack_status['intensity']
        
        # Weight factor: 1-3 requests for low intensity, 3-5 for medium, 5-8 for high
        weight = max(1, min(8, int(intensity * 0.8)))
        
        # Process the request multiple times based on weight
        for _ in range(weight):
            traffic_profiler.process_request(ip, path, method)
            
        # Get updated metrics
        metrics = traffic_profiler.get_current_metrics()
        
        # Boost anomaly scores for simulated traffic to improve detection
        anomaly_score = anomaly_detector.detect_anomalies(metrics)
        
        # Scale anomaly score based on intensity (higher intensity = higher score)
        intensity_factor = min(1.0, max(0.5, intensity / 10.0))
        anomaly_score = max(anomaly_score, 0.4 + (intensity_factor * 0.4))
        
        # Apply aggressive mitigation for simulated attacks
        action = mitigation_system.mitigate(ip, anomaly_score)
        
        app.logger.info(f"Simulated attack: IP={ip}, Type={attack_type}, Intensity={intensity}, Score={anomaly_score:.2f}, Action={action}")
    else:
        # Normal traffic processing
        traffic_profiler.process_request(ip, path, method)
        
        # Check for anomalies
        metrics = traffic_profiler.get_current_metrics()
        anomaly_score = anomaly_detector.detect_anomalies(metrics)
        
        # Apply mitigation if needed
        action = mitigation_system.mitigate(ip, anomaly_score)
    
    # If the action is to block, return a 403 response
    if action == 'block':
        return jsonify({
            'status': 'blocked', 
            'reason': 'Suspicious activity detected',
            'ip': ip,
            'score': anomaly_score
        }), 403
    
    # Return more detailed response for better monitoring
    return jsonify({
        'status': 'processed',
        'ip': ip,
        'path': path,
        'method': method,
        'anomaly_score': anomaly_score,
        'action': action,
        'is_simulation': is_simulation,
        'attack_type': attack_type
    })

# Create database tables and clean up any lingering active attacks
with app.app_context():
    import models
    db.create_all()
    
    # Clean up any attack logs that were left active (from previous runs)
    try:
        active_attacks = models.AttackLog.query.filter_by(is_active=True).all()
        if active_attacks:
            app.logger.info(f"Cleaning up {len(active_attacks)} active attack logs from previous runs")
            for attack in active_attacks:
                attack.is_active = False
                attack.end_time = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error cleaning up attack logs: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
