import os
import logging
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

# API endpoints
@app.route('/api/traffic/current', methods=['GET'])
def get_current_traffic():
    return jsonify(traffic_profiler.get_current_metrics())

@app.route('/api/traffic/history', methods=['GET'])
def get_traffic_history():
    return jsonify(traffic_profiler.get_traffic_history())

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    return jsonify(anomaly_detector.get_anomalies())

@app.route('/api/mitigation/status', methods=['GET'])
def get_mitigation_status():
    return jsonify(mitigation_system.get_status())

@app.route('/api/mitigation/blocked', methods=['GET'])
def get_blocked_ips():
    return jsonify(mitigation_system.get_blocked_ips())

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
    attack_simulator.stop_attack()
    return jsonify({'status': 'Attack simulation stopped'})

@app.route('/api/simulate/status', methods=['GET'])
def get_attack_status():
    return jsonify(attack_simulator.get_attack_status())

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
    ip = request.remote_addr
    path = request.path
    method = request.method
    
    # Process the request through our monitoring system
    traffic_profiler.process_request(ip, path, method)
    
    # Check for anomalies
    anomaly_score = anomaly_detector.detect_anomalies(traffic_profiler.get_current_metrics())
    
    # Apply mitigation if needed
    action = mitigation_system.mitigate(ip, anomaly_score)
    
    # If the action is to block, return a 403 response
    if action == 'block':
        return jsonify({'status': 'blocked', 'reason': 'Suspicious activity detected'}), 403
    
    # For demonstration purposes, return a simple response
    return jsonify({'status': 'processed'})

# Create database tables
with app.app_context():
    import models
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
