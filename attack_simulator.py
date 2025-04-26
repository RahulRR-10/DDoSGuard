import logging
import random
import threading
import time
import requests
from datetime import datetime
from models import AttackLog
from app import db

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
        if self.is_running:
            self.logger.info("Attack already in progress, stopping current attack")
            self.stop_attack()
        
        self.logger.info(f"Starting {attack_type} attack simulation (duration: {duration}s, intensity: {intensity})")
        
        # Create attack log entry
        try:
            attack_log = AttackLog(
                attack_type=attack_type,
                intensity=intensity,
                distribution=distribution,
                is_active=True
            )
            db.session.add(attack_log)
            db.session.commit()
            self.current_attack = attack_log
        except Exception as e:
            self.logger.error(f"Error logging attack start: {str(e)}")
            db.session.rollback()
        
        # Reset stop event
        self.stop_event.clear()
        
        # Select attack function
        attack_func = self.attack_types.get(attack_type, self._flooding_attack)
        
        # Start attack in separate thread
        self.attack_thread = threading.Thread(
            target=self._run_attack,
            args=(attack_func, duration, intensity, distribution)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
        self.is_running = True
    
    def stop_attack(self):
        """Stop any ongoing attack simulation."""
        if not self.is_running:
            return
        
        self.logger.info("Stopping attack simulation")
        self.stop_event.set()
        
        if self.attack_thread:
            self.attack_thread.join(timeout=2.0)
        
        self.is_running = False
        
        # Update attack log
        if self.current_attack:
            try:
                self.current_attack.end_time = datetime.utcnow()
                self.current_attack.is_active = False
                db.session.commit()
            except Exception as e:
                self.logger.error(f"Error updating attack log: {str(e)}")
                db.session.rollback()
    
    def _run_attack(self, attack_func, duration, intensity, distribution):
        """
        Run the attack function for the specified duration.
        
        Args:
            attack_func (function): Attack function to run
            duration (int): Duration in seconds
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        start_time = time.time()
        end_time = start_time + duration
        
        try:
            while time.time() < end_time and not self.stop_event.is_set():
                attack_func(intensity, distribution)
                
                # Check if we should stop
                if self.stop_event.wait(0.1):
                    break
            
            self.logger.info("Attack simulation completed")
        except Exception as e:
            self.logger.error(f"Error in attack simulation: {str(e)}")
        finally:
            self.is_running = False
    
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
                requests.get(
                    'http://localhost:5000/process_request',
                    headers={'X-Forwarded-For': ip},
                    timeout=0.5
                )
            except requests.exceptions.RequestException:
                pass
            
            # Small delay between requests
            time.sleep(0.01)
    
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
                requests.get(
                    'http://localhost:5000/process_request',
                    headers={'X-Forwarded-For': ip},
                    timeout=0.5
                )
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(0.005)  # Very small delay during burst
        
        # Pause between bursts
        time.sleep(1.0)
    
    def _slowloris_attack(self, intensity, distribution):
        """
        Simulate a Slowloris-like attack with incomplete requests.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # Number of parallel connections
        num_connections = intensity * 2  # 2-20 connections
        
        for _ in range(num_connections):
            if self.stop_event.is_set():
                break
            
            ip = self._generate_ip(distribution)
            
            # Simulate partial request
            try:
                session = requests.Session()
                session.get(
                    'http://localhost:5000/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'Connection': 'keep-alive'
                    },
                    timeout=0.5,
                    stream=True  # Keep connection open
                )
                # Don't read the response or close the connection
            except requests.exceptions.RequestException:
                pass
        
        # Keep connections open for a while
        time.sleep(0.5)
    
    def _syn_flood_simulation(self, intensity, distribution):
        """
        Simulate a SYN flood attack (can't actually do TCP-level attacks, so we simulate).
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern
        """
        # We can't do real SYN floods, so just simulate with API calls
        num_requests = intensity * 8  # 8-80 requests
        
        for _ in range(num_requests):
            if self.stop_event.is_set():
                break
            
            ip = self._generate_ip(distribution)
            
            # Simulate SYN flood by sending request with SYN header
            try:
                requests.get(
                    'http://localhost:5000/process_request',
                    headers={
                        'X-Forwarded-For': ip,
                        'X-Attack-Type': 'syn_flood'  # Custom header for simulation
                    },
                    timeout=0.1
                )
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(0.01)
    
    def _distributed_attack(self, intensity, distribution):
        """
        Simulate a distributed attack from many sources.
        
        Args:
            intensity (int): Attack intensity (1-10)
            distribution (str): IP distribution pattern (ignored, always uses random IPs)
        """
        # Always use random distribution for this attack type
        num_requests = intensity * 7  # 7-70 requests
        
        for _ in range(num_requests):
            if self.stop_event.is_set():
                break
            
            # Always use random IPs for distributed attack
            ip = self._generate_ip('random')
            
            # Random URL paths to simulate different targets
            paths = ['/login', '/api/data', '/search', '/user', '/admin', '/process_request']
            path = random.choice(paths)
            
            try:
                requests.get(
                    f'http://localhost:5000{path}',
                    headers={'X-Forwarded-For': ip},
                    timeout=0.5
                )
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(0.02)
    
    def get_attack_status(self):
        """
        Get the status of the current attack.
        
        Returns:
            dict: Attack status information
        """
        return {
            'is_running': self.is_running,
            'attack_type': self.current_attack.attack_type if self.current_attack else None,
            'start_time': self.current_attack.start_time if self.current_attack else None,
            'intensity': self.current_attack.intensity if self.current_attack else None,
            'distribution': self.current_attack.distribution if self.current_attack else None
        }
    
    def get_attack_types(self):
        """
        Get the list of available attack types.
        
        Returns:
            list: List of attack type strings
        """
        return list(self.attack_types.keys())
