from app import db
from datetime import datetime

class TrafficLog(db.Model):
    """Model to store traffic logs for analysis"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 can be up to 45 chars
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    path = db.Column(db.String(255))
    method = db.Column(db.String(10))
    
    def __repr__(self):
        return f'<TrafficLog {self.ip_address} at {self.timestamp}>'

class AnomalyLog(db.Model):
    """Model to store detected anomalies"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    anomaly_score = db.Column(db.Float, nullable=False)
    entropy_value = db.Column(db.Float)
    burst_score = db.Column(db.Float)
    unique_ips = db.Column(db.Integer)
    total_requests = db.Column(db.Integer)
    
    def __repr__(self):
        return f'<AnomalyLog {self.timestamp} score: {self.anomaly_score}>'

class BlockedIP(db.Model):
    """Model to store blocked IP addresses"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(255))
    severity = db.Column(db.String(20))  # light, medium, severe
    expiration = db.Column(db.DateTime, nullable=True)  # When the block expires, null for permanent
    
    def __repr__(self):
        return f'<BlockedIP {self.ip_address} severity: {self.severity}>'

class TrafficMetrics(db.Model):
    """Model to store historical traffic metrics"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    requests_per_second = db.Column(db.Float)
    unique_ips = db.Column(db.Integer)
    entropy_value = db.Column(db.Float)
    burst_score = db.Column(db.Float)
    
    def __repr__(self):
        return f'<TrafficMetrics {self.timestamp} rps: {self.requests_per_second}>'

class BaselineProfile(db.Model):
    """Model to store baseline traffic profiles"""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    avg_requests_per_second = db.Column(db.Float)
    avg_unique_ips = db.Column(db.Float)
    avg_entropy = db.Column(db.Float)
    std_requests_per_second = db.Column(db.Float)
    std_unique_ips = db.Column(db.Float)
    std_entropy = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<BaselineProfile {self.created_at} active: {self.is_active}>'

class AttackLog(db.Model):
    """Model to store simulated attack logs"""
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    attack_type = db.Column(db.String(50))
    intensity = db.Column(db.Integer)
    distribution = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<AttackLog {self.attack_type} at {self.start_time}>'
