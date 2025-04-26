import logging
import threading
import time
import random
import requests
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
from flask import abort, request, jsonify

# Import DB from app module
try:
    from app import db
except ImportError:
    db = None

class AttackSimulator:
    """
    Attack Simulation Lab to test the DDoS detection and mitigation system
    by generating realistic attack traffic.
    """
    
    def __init__(self):
        """Initialize the Attack Simulator."""
        self.logger = logging.getLogger(__name__)
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.attack_types = {
            'flooding': self._flooding_attack,
            'pulsing': self._pulsing_attack,
            'slowloris': self._slowloris_attack,
            'syn_flood': self._syn_flood_simulation,
            'distributed': self._distributed_attack
        }
        self.is_running = False
        self.current_attack = None
        
        # Persistent attack parameters
        self.attack_type = None
        self.attack_duration = None
        self.attack_intensity = None
        self.attack_distribution = None
        self.attack_start_time = None
        
        self.logger.info("Attack Simulator initialized")
    
    def start_attack(self, attack_type='flooding', duration=60, intensity=5, distribution='random'):
        """
        Start a simulated attack.
        
        Args:
            attack_type (str): Type of attack to simulate ('flooding', 'pulsing', etc.)
            duration (int): Duration of attack in seconds
            intensity (int): Attack intensity level (1-10)
            distribution (str): IP distribution pattern ('random', 'subnet', 'fixed')
        """
        self.logger.debug(f"[DEBUG] start_attack called with is_running={self.is_running}")
        if self.is_running:
            self.logger.info("Attack already in progress, stopping current attack")
            self.stop_attack()
        
        self.logger.info(f"Starting {attack_type} attack simulation (duration: {duration}s, intensity: {intensity})")
        
        # Set basic status even before DB operations
        self.is_running = True
        self.logger.debug(f"[DEBUG] is_running set to True in start_attack")
        self.attack_type = attack_type
        self.attack_intensity = intensity
        self.attack_distribution = distribution
        self.attack_duration = duration
        self.attack_start_time = datetime.utcnow()
        
        # Create attack log entry
        try:
            from app import app
            with app.app_context():
                from models import AttackLog
                attack_log = AttackLog(
                    attack_type=attack_type,
                    intensity=intensity,
                    distribution=distribution,
                    is_active=True
                )
                db.session.add(attack_log)
                db.session.commit()
                self.current_attack = attack_log
                self.logger.info(f"Created attack log with ID: {attack_log.id}")
        except Exception as e:
            self.logger.error(f"Error logging attack start: {str(e)}")
            try:
                db.session.rollback()
            except:
                pass
        
        # Reset stop event
        self.stop_event.clear()
        
        # Select attack function
        attack_func = self.attack_types.get(attack_type, self._flooding_attack)
        
        # Start attack in separate thread
        self.logger.debug(f"[DEBUG] About to start attack thread")
        self.attack_thread = threading.Thread(
            target=self._run_attack,
            args=(attack_func, duration, intensity, distribution)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
        self.logger.debug(f"[DEBUG] Attack thread started")
        
        self.is_running = True
        self.logger.debug(f"[DEBUG] is_running confirmed True after thread start")
    
    def stop_attack(self):
        """Stop any ongoing attack simulation."""
        if not self.is_running:
            return
        
        self.logger.info("Stopping attack simulation")
        self.stop_event.set()
        
        if self.attack_thread:
            self.attack_thread.join(timeout=2.0)
        
        self.is_running = False
        
        # Update attack log with proper app context
        if self.current_attack:
            try:
                from app import app
                with app.app_context():
                    from models import AttackLog
                    
                    # Get fresh instance from database
                    attack_id = self.current_attack.id
                    attack_log = AttackLog.query.filter_by(id=attack_id).first()
                    
                    if attack_log:
                        attack_log.end_time = datetime.utcnow()
                        attack_log.is_active = False
                        db.session.commit()
                        self.logger.info(f"Successfully updated attack log ID {attack_id} to inactive")
                    else:
                        self.logger.warning(f"Could not find attack log with ID {attack_id}")
            except Exception as e:
                self.logger.error(f"Error updating attack log: {str(e)}")
                try:
                    db.session.rollback()
                except:
                    pass
    
    def _run_attack(self, attack_func, duration, intensity, distribution):
        """
        Run the attack function for the specified duration.
        
        Args:
            attack_func (function): Attack function to run
            duration (int): Duration in seconds
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        self.logger.info(f"_run_attack started - attack will run for {duration} seconds with intensity {intensity}")
        start_time = time.time()
        end_time = start_time + duration
        
        try:
            # Update the attack log with the duration
            if self.current_attack:
                try:
                    from app import app
                    with app.app_context():
                        from models import AttackLog
                        
                        # Get fresh instance to avoid detached instance issues
                        attack_id = self.current_attack.id
                        attack_log = AttackLog.query.get(attack_id)
                        if attack_log:
                            attack_log.end_time = datetime.utcnow() + timedelta(seconds=duration)
                            db.session.commit()
                            self.logger.info(f"Updated attack log with duration: {duration}s")
                except Exception as e:
                    self.logger.error(f"Error updating attack log duration: {str(e)}")
                    try:
                        from app import app
                        with app.app_context():
                            db.session.rollback()
                    except:
                        self.logger.error("Could not rollback session")
            
            # Run the attack
            attack_iteration = 0
            while time.time() < end_time and not self.stop_event.is_set():
                attack_iteration += 1
                # Log every 10 iterations
                if attack_iteration % 10 == 0:
                    elapsed = int(time.time() - start_time)
                    remaining = duration - elapsed
                    self.logger.info(f"Attack in progress: iteration {attack_iteration}, {elapsed}s elapsed, {remaining}s remaining")
                
                # Call the attack function with the parameters
                attack_func(intensity, distribution)
                
                # Check if we should stop
                if self.stop_event.wait(0.1):
                    self.logger.info("Attack stopped manually through stop_event")
                    break
            
            # Check if we reached the end naturally or were stopped
            if time.time() >= end_time:
                self.logger.info(f"Attack simulation completed - reached full duration of {duration}s")
            
        except Exception as e:
            self.logger.error(f"Error in attack simulation: {str(e)}")
        finally:
            # Only set is_running to False if we actually completed
            if time.time() >= end_time or self.stop_event.is_set():
                self.is_running = False
                self.logger.info("Attack finished - setting is_running=False")
            else:
                self.logger.warning("Attack thread terminating but attack should still be running")
            
            # Ensure the attack log is properly marked as completed
            if self.current_attack:
                try:
                    from app import app
                    with app.app_context():
                        from models import AttackLog
                        
                        attack_id = self.current_attack.id
                        attack_log = AttackLog.query.get(attack_id)
                        if attack_log:
                            attack_log.end_time = datetime.utcnow()
                            attack_log.is_active = False
                            db.session.commit()
                            self.logger.info(f"Successfully finalized attack log ID {attack_id}")
                except Exception as e:
                    self.logger.error(f"Error finalizing attack log: {str(e)}")
                    try:
                        from app import app
                        with app.app_context():
                            db.session.rollback()
                    except:
                        self.logger.error("Could not rollback session")
    
    def _generate_ip(self, distribution):
        """
        Generate an IP address based on the distribution pattern.
        
        Args:
            distribution (str): IP distribution pattern
            
        Returns:
            str: Generated IP address
        """
        if distribution == 'fixed':
            # Single source attack
            return '192.168.1.100'
        
        elif distribution == 'subnet':
            # Subnet-based attack (looks like it's coming from the same network)
            return f'192.168.1.{random.randint(1, 254)}'
        
        else:  # 'random'
            # Fully distributed attack
            return f'{random.randint(1, 254)}.{random.randint(1, 254)}.' \
                   f'{random.randint(1, 254)}.{random.randint(1, 254)}'
    
    def _flooding_attack(self, intensity, distribution):
        """
        Simulate a basic flooding attack.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # Determine number of requests based on intensity (1-10)
        num_requests = intensity * 5  # 5-50 requests per batch
        
        for _ in range(num_requests):
            if self.stop_event.is_set():
                break
            
            # Generate spoofed IP
            ip = self._generate_ip(distribution)
            
            # Send request to the monitoring endpoint
            try:
                # Use direct function call instead of HTTP request to avoid network issues
                from app import process_request, app
                with app.test_request_context(
                    path='/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'flooding'  # Mark as attack traffic
                    }
                ):
                    process_request()
                
                # Log every 10th request to avoid overwhelming the logs
                if _ % 10 == 0:
                    self.logger.info(f"Sent flooding attack request from {ip} ({_+1}/{num_requests})")
            except Exception as e:
                self.logger.error(f"Error sending simulated request: {str(e)}")
                pass
            
            # Small delay between requests (using a smaller delay for flooding attacks)
            time.sleep(0.005)
    
    def _pulsing_attack(self, intensity, distribution):
        """
        Simulate a pulsing attack with bursts of traffic.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # Pulsing pattern: burst of traffic, then pause
        burst_requests = intensity * 10  # 10-100 requests per burst
        
        # First burst
        for _ in range(burst_requests):
            if self.stop_event.is_set():
                break
            
            ip = self._generate_ip(distribution)
            
            try:
                # Use direct function call instead of HTTP request to avoid network issues
                from app import process_request, app
                with app.test_request_context(
                    path='/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'pulsing'  # Mark as pulsing attack traffic
                    }
                ):
                    process_request()
                
                # Log every 20th request to avoid overwhelming the logs
                if _ % 20 == 0:
                    self.logger.info(f"Sent pulsing attack request from {ip} ({_+1}/{burst_requests})")
            except Exception as e:
                self.logger.error(f"Error sending simulated request: {str(e)}")
                pass
            
            # Small delay between requests
            time.sleep(0.001)
        
        # Pause between bursts (typical of pulsing attacks)
        time.sleep(0.5)
    
    def _slowloris_attack(self, intensity, distribution):
        """
        Simulate a Slowloris-like attack with incomplete requests.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # Fewer connections but they stay open longer
        num_connections = intensity * 2  # 2-20 connections
        
        for _ in range(num_connections):
            if self.stop_event.is_set():
                break
            
            ip = self._generate_ip(distribution)
            
            # Simulate a slow, incomplete request
            try:
                from app import process_request, app
                with app.test_request_context(
                    path='/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'slowloris',  # Mark as slowloris attack traffic
                        'Content-Length': '10000',  # Large content length but sending incomplete data
                        'Keep-Alive': 'timeout=30'  # Long keep-alive
                    }
                ):
                    process_request()
                
                self.logger.info(f"Sent slowloris attack request from {ip} ({_+1}/{num_connections})")
            except Exception as e:
                self.logger.error(f"Error sending simulated request: {str(e)}")
                pass
            
            # Longer delay to simulate holding connections open
            time.sleep(0.2)
    
    def _syn_flood_simulation(self, intensity, distribution):
        """
        Simulate a SYN flood attack (can't actually do TCP-level attacks, so we simulate).
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # Many connection attempts that never complete
        num_syn_packets = intensity * 15  # 15-150 SYN packets
        
        for _ in range(num_syn_packets):
            if self.stop_event.is_set():
                break
            
            ip = self._generate_ip(distribution)
            
            try:
                # Use direct function call instead of HTTP request to avoid network issues
                from app import process_request, app
                with app.test_request_context(
                    path='/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'syn_flood',  # Mark as SYN flood attack traffic
                        'Connection': 'Incomplete'  # Simulate incomplete connection
                    }
                ):
                    process_request()
                
                # Log every 15th request to avoid overwhelming the logs
                if _ % 15 == 0:
                    self.logger.info(f"Sent SYN flood attack request from {ip} ({_+1}/{num_syn_packets})")
            except Exception as e:
                self.logger.error(f"Error sending simulated request: {str(e)}")
                pass
            
            # Very small delay to simulate rapid SYN packet sending
            time.sleep(0.002)
    
    def _distributed_attack(self, intensity, distribution):
        """
        Simulate a distributed attack from many sources.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern (ignored, always uses random IPs)
        """
        # A distributed attack always uses random IPs, regardless of the distribution parameter
        num_requests = intensity * 8  # 8-80 requests
        
        for _ in range(num_requests):
            if self.stop_event.is_set():
                break
            
            # Always use fully random IPs for distributed attacks
            ip = f'{random.randint(1, 254)}.{random.randint(1, 254)}.' \
                 f'{random.randint(1, 254)}.{random.randint(1, 254)}'
            
            # Random URL paths to simulate different targets
            paths = ['/login', '/api/data', '/search', '/user', '/admin', '/process_request']
            path = random.choice(paths)
            
            try:
                # Use direct function call instead of HTTP request to avoid network issues
                from app import process_request, app
                with app.test_request_context(
                    path=path,
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'distributed'  # Mark as distributed attack
                    }
                ):
                    process_request()
                
                # Log periodically
                if _ % 10 == 0:
                    self.logger.info(f"Sent distributed attack request from {ip} to {path} ({_+1}/{num_requests})")
            except Exception as e:
                self.logger.error(f"Error sending simulated request: {str(e)}")
                pass
            
            # Distributed attacks often have slightly variable timing
            time.sleep(0.01 + random.random() * 0.03)
    
    def get_attack_status(self):
        """
        Get the status of the current attack.
        
        Returns:
            dict: Attack status information
        """
        try:
            # First check if attack is running based on our thread
            if not self.is_running:
                # Still return last attack parameters even when not running
                # This helps maintain consistency between page navigation
                return {
                    'is_running': False,
                    'attack_type': self.attack_type,
                    'start_time': self.attack_start_time.isoformat() if self.attack_start_time else None,
                    'intensity': self.attack_intensity,
                    'distribution': self.attack_distribution,
                    'duration': self.attack_duration
                }
            
            # Attack is running, return all parameters
            return {
                'is_running': True,
                'attack_type': self.attack_type or 'flooding',
                'start_time': self.attack_start_time.isoformat() if self.attack_start_time else datetime.utcnow().isoformat(),
                'intensity': self.attack_intensity or 5, 
                'distribution': self.attack_distribution or 'random',
                'duration': self.attack_duration or 60
            }
        except Exception as e:
            self.logger.error(f"Error getting attack status: {str(e)}")
            # Return safe defaults
            return {
                'is_running': False,
                'attack_type': None,
                'start_time': None,
                'intensity': None,
                'distribution': None,
                'duration': None
            }
    
    def get_attack_types(self):
        """
        Get the list of available attack types.
        
        Returns:
            list: List of attack type strings
        """
        return list(self.attack_types.keys())