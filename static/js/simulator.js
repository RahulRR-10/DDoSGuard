// Simulator.js - Handles the attack simulation functionality

// Global variables for timer
let attackTimer = null;
let attackStartTime = null;
let attackDuration = 0;

// Get saved timer state from sessionStorage
const savedAttackStartTime = sessionStorage.getItem('attackStartTime');
const savedAttackDuration = sessionStorage.getItem('attackDuration');

document.addEventListener('DOMContentLoaded', function() {
    console.log('Simulator initializing...');
    
    // Initialize event listeners
    document.getElementById('startAttackBtn').addEventListener('click', startAttack);
    document.getElementById('stopAttackBtn').addEventListener('click', stopAttack);
    
    // Initialize attack parameter controls
    initAttackTypeSelector();
    initDurationSlider();
    initIntensitySlider();
    initDistributionSelector();
    
    // Create timer display element if it doesn't exist
    if (!document.getElementById('attackTimerDisplay')) {
        const timerContainer = document.createElement('div');
        timerContainer.id = 'attackTimerContainer';
        timerContainer.className = 'mt-3 d-none';
        timerContainer.innerHTML = `
            <div class="card border-danger">
                <div class="card-body p-2 text-center">
                    <h5 class="card-title mb-1">Attack Timer</h5>
                    <div class="d-flex justify-content-center align-items-center">
                        <div id="attackTimerDisplay" class="display-4 mb-0 text-danger">00:00</div>
                    </div>
                    <small class="text-muted">Time Elapsed / Total Duration</small>
                </div>
            </div>
        `;
        
        // Add timer after attack details
        const detailsContainer = document.getElementById('attackDetailsContainer');
        detailsContainer.parentNode.insertBefore(timerContainer, detailsContainer.nextSibling);
    }
    
    // Log the session storage state for debugging
    console.log('Session storage state on page load:', {
        running: sessionStorage.getItem('attackRunning'),
        startTime: sessionStorage.getItem('attackStartTime'),
        duration: sessionStorage.getItem('attackDuration')
    });
    
    // Restore timer state if we have session data
    if (savedAttackStartTime && sessionStorage.getItem('attackRunning') === 'true') {
        // Convert ISO start time to Date
        attackStartTime = new Date(savedAttackStartTime);
        
        // Get duration from session storage
        if (savedAttackDuration) {
            attackDuration = parseInt(savedAttackDuration);
        }
        
        // Start the timer immediately instead of waiting for checkAttackStatus to complete
        startAttackTimer();
    }
    
    // Then check the server for the actual attack status (this will override session storage if needed)
    checkAttackStatus();
    
    // Set up regular status check
    setInterval(checkAttackStatus, 5000); // Check every 5 seconds
});

function initAttackTypeSelector() {
    const attackTypeSelector = document.getElementById('attackType');
    
    // Define attack types with descriptions
    const attackTypes = [
        { value: 'flooding', name: 'Distributed Flooding', description: 'High-volume traffic from multiple sources' },
        { value: 'pulsing', name: 'Pulsing Attack', description: 'Bursts of traffic followed by pauses' },
        { value: 'slowloris', name: 'Slowloris', description: 'Slow HTTP headers to keep connections open' },
        { value: 'syn_flood', name: 'SYN Flood', description: 'TCP SYN packet flood simulation' },
        { value: 'distributed', name: 'Mixed Distribution', description: 'Varied attack vectors from many sources' }
    ];
    
    // Add options to select
    attackTypes.forEach(type => {
        const option = document.createElement('option');
        option.value = type.value;
        option.textContent = type.name;
        attackTypeSelector.appendChild(option);
    });
    
    // Add event listener to update description
    attackTypeSelector.addEventListener('change', function() {
        const selectedType = this.value;
        const description = attackTypes.find(type => type.value === selectedType)?.description || '';
        document.getElementById('attackTypeDescription').textContent = description;
    });
    
    // Trigger change to set initial description
    attackTypeSelector.dispatchEvent(new Event('change'));
}

function initDurationSlider() {
    const durationSlider = document.getElementById('duration');
    const durationValue = document.getElementById('durationValue');
    
    // Set initial value
    durationValue.textContent = `${durationSlider.value} seconds`;
    
    // Add event listener for slider changes
    durationSlider.addEventListener('input', function() {
        durationValue.textContent = `${this.value} seconds`;
    });
}

function initIntensitySlider() {
    const intensitySlider = document.getElementById('intensity');
    const intensityValue = document.getElementById('intensityValue');
    
    // Set initial value
    intensityValue.textContent = intensitySlider.value;
    
    // Add event listener for slider changes
    intensitySlider.addEventListener('input', function() {
        intensityValue.textContent = this.value;
        
        // Update visual indicator
        updateIntensityIndicator(parseInt(this.value));
    });
    
    // Initialize visual indicator
    updateIntensityIndicator(parseInt(intensitySlider.value));
}

function updateIntensityIndicator(value) {
    const indicator = document.getElementById('intensityIndicator');
    
    // Reset classes
    indicator.className = 'progress-bar';
    
    // Set width based on value
    indicator.style.width = `${value * 10}%`;
    
    // Set color based on intensity
    if (value <= 3) {
        indicator.classList.add('bg-success');
    } else if (value <= 6) {
        indicator.classList.add('bg-warning');
    } else {
        indicator.classList.add('bg-danger');
    }
}

function initDistributionSelector() {
    const distributionSelector = document.getElementById('distribution');
    
    // Define distributions with descriptions
    const distributions = [
        { value: 'random', name: 'Random IPs', description: 'Attack from completely random IP addresses' },
        { value: 'subnet', name: 'Subnet-based', description: 'Attack from IPs within the same subnet' },
        { value: 'fixed', name: 'Fixed Source', description: 'Attack from a single source IP address' }
    ];
    
    // Add options to select
    distributions.forEach(dist => {
        const option = document.createElement('option');
        option.value = dist.value;
        option.textContent = dist.name;
        distributionSelector.appendChild(option);
    });
    
    // Add event listener to update description
    distributionSelector.addEventListener('change', function() {
        const selectedDist = this.value;
        const description = distributions.find(dist => dist.value === selectedDist)?.description || '';
        document.getElementById('distributionDescription').textContent = description;
    });
    
    // Trigger change to set initial description
    distributionSelector.dispatchEvent(new Event('change'));
}

function startAttack() {
    // Get attack parameters
    const attackType = document.getElementById('attackType').value;
    const duration = document.getElementById('duration').value;
    const intensity = document.getElementById('intensity').value;
    const distribution = document.getElementById('distribution').value;
    
    // Create request body
    const requestBody = {
        attack_type: attackType,
        duration: duration,
        intensity: intensity,
        distribution: distribution
    };
    
    // Update UI to show loading
    document.getElementById('startAttackBtn').disabled = true;
    document.getElementById('startAttackBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Send request to start attack
    fetch('/api/simulate/attack', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Attack simulation started:', data);
        
        // Update UI
        updateSimulationStatus(true, attackType, duration, intensity, distribution, data);
        
        // Show alert with dashboard link
        showAlert(`
            <div class="d-flex justify-content-between align-items-center">
                <span>Attack simulation started successfully</span>
                <a href="/dashboard" class="btn btn-sm btn-outline-light ms-3">
                    <i class="fas fa-tachometer-alt me-1"></i>View Effects on Dashboard
                </a>
            </div>
        `, 'success');
    })
    .catch(error => {
        console.error('Error starting attack simulation:', error);
        
        // Show error alert
        showAlert('Failed to start attack simulation', 'danger');
        
        // Reset UI
        document.getElementById('startAttackBtn').disabled = false;
        document.getElementById('startAttackBtn').textContent = 'Start Attack';
    });
}

function stopAttack() {
    // Update UI to show loading
    document.getElementById('stopAttackBtn').disabled = true;
    document.getElementById('stopAttackBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Stopping...';
    
    // Send request to stop attack
    fetch('/api/simulate/stop', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Attack simulation stopped:', data);
        
        // Update UI
        updateSimulationStatus(false);
        
        // Show alert
        showAlert('Attack simulation stopped successfully', 'info');
    })
    .catch(error => {
        console.error('Error stopping attack simulation:', error);
        
        // Show error alert
        showAlert('Failed to stop attack simulation', 'danger');
        
        // Reset UI
        document.getElementById('stopAttackBtn').disabled = false;
        document.getElementById('stopAttackBtn').textContent = 'Stop Attack';
    });
}

function checkAttackStatus() {
    // Fetch the current attack status from the server
    fetch('/api/simulate/status')
        .then(response => response.json())
        .then(data => {
            if (data.is_running) {
                // Store attack details in session storage for persistence between page loads
                sessionStorage.setItem('attackRunning', 'true');
                sessionStorage.setItem('attackType', data.attack_type);
                sessionStorage.setItem('attackDuration', data.duration);
                sessionStorage.setItem('attackIntensity', data.intensity);
                sessionStorage.setItem('attackDistribution', data.distribution);
                
                // If we have a start time in the API response, store it
                if (data.start_time) {
                    sessionStorage.setItem('attackStartTime', data.start_time);
                }
                
                // Update UI to show attack is running
                updateSimulationStatus(
                    true,
                    data.attack_type,
                    data.duration,
                    data.intensity,
                    data.distribution,
                    data // Pass the full data object for access to start_time
                );
            } else {
                // If the attack is not running, clear session storage
                sessionStorage.removeItem('attackRunning');
                
                // Don't clear other values as they might be needed for displaying
                // historical data about the last attack that ran
                
                updateSimulationStatus(false);
            }
        })
        .catch(error => {
            console.error('Error checking attack status:', error);
        });
}

function updateSimulationStatus(isRunning, attackType = '', duration = 0, intensity = 0, distribution = '', data = null) {
    console.log('updateSimulationStatus called:', {isRunning, attackType, duration, intensity, distribution, data});
    
    const statusContainer = document.getElementById('attackStatusContainer');
    const statusBadge = document.getElementById('attackStatusBadge');
    const attackForm = document.getElementById('attackForm');
    const startButton = document.getElementById('startAttackBtn');
    const stopButton = document.getElementById('stopAttackBtn');
    const attackDetails = document.getElementById('attackDetails');
    const timerContainer = document.getElementById('attackTimerContainer');
    
    if (isRunning) {
        // Show running status
        statusContainer.style.display = 'block';
        statusBadge.textContent = 'ATTACK RUNNING';
        statusBadge.className = 'badge bg-danger';
        
        // Disable form controls
        Array.from(attackForm.elements).forEach(element => {
            element.disabled = true;
        });
        
        // Update buttons
        startButton.disabled = true;
        startButton.textContent = 'Attack Running';
        stopButton.disabled = false;
        stopButton.textContent = 'Stop Attack';
        
        // Show attack details
        const attackName = document.getElementById('attackType').options.namedItem(attackType) ?
                          document.getElementById('attackType').options.namedItem(attackType).text :
                          attackType;
        
        const distributionName = document.getElementById('distribution').options.namedItem(distribution) ?
                               document.getElementById('distribution').options.namedItem(distribution).text :
                               distribution;
        
        attackDetails.innerHTML = `
            <strong>Attack Type:</strong> ${attackName}<br>
            <strong>Duration:</strong> ${duration} seconds<br>
            <strong>Intensity:</strong> ${intensity}/10<br>
            <strong>Distribution:</strong> ${distributionName}
        `;
        
        document.getElementById('attackDetailsContainer').style.display = 'block';
        
        // Start or update the timer
        if (timerContainer) {
            timerContainer.className = 'mt-3';
            
            // Store the attack duration for the timer
            attackDuration = parseInt(duration);
            
            // If timer is not running, start it
            if (!attackTimer) {
                console.log('No active timer, starting new timer');
                
                // Get the most accurate start time - prefer server value if available
                if (data && data.start_time) {
                    console.log('Using server start time:', data.start_time);
                    attackStartTime = new Date(data.start_time);
                } else if (savedAttackStartTime && sessionStorage.getItem('attackRunning') === 'true') {
                    console.log('Using saved start time:', savedAttackStartTime);
                    attackStartTime = new Date(savedAttackStartTime);
                } else {
                    console.log('Using current time as start time');
                    attackStartTime = new Date();
                }
                
                // Debug current timer state
                console.log('Timer state before starting:', {
                    startTime: attackStartTime,
                    duration: attackDuration,
                });
                
                // Start the timer
                startAttackTimer();
            } else {
                console.log('Timer already running, not restarting');
            }
        }
    } else {
        // Show idle status
        statusContainer.style.display = 'block';
        statusBadge.textContent = 'IDLE';
        statusBadge.className = 'badge bg-secondary';
        
        // Enable form controls
        Array.from(attackForm.elements).forEach(element => {
            element.disabled = false;
        });
        
        // Update buttons
        startButton.disabled = false;
        startButton.textContent = 'Start Attack';
        stopButton.disabled = true;
        stopButton.textContent = 'Stop Attack';
        
        // Hide attack details
        document.getElementById('attackDetailsContainer').style.display = 'none';
        
        // Stop the timer
        if (attackTimer) {
            clearInterval(attackTimer);
            attackTimer = null;
        }
        
        // Hide timer container
        if (timerContainer) {
            timerContainer.className = 'mt-3 d-none';
        }
    }
}

function startAttackTimer() {
    // Clear any existing timer
    if (attackTimer) {
        clearInterval(attackTimer);
    }
    
    // Save attack start time and duration to session storage for persistence
    sessionStorage.setItem('attackStartTime', attackStartTime.toISOString());
    sessionStorage.setItem('attackDuration', attackDuration.toString());
    sessionStorage.setItem('attackRunning', 'true');
    
    console.log('Timer started - saved to session storage:', {
        startTime: sessionStorage.getItem('attackStartTime'),
        duration: sessionStorage.getItem('attackDuration'),
        running: sessionStorage.getItem('attackRunning')
    });
    
    // Update timer display immediately
    updateTimerDisplay();
    
    // Set up timer to update every second
    attackTimer = setInterval(updateTimerDisplay, 1000);
}

function updateTimerDisplay() {
    const timerDisplay = document.getElementById('attackTimerDisplay');
    if (!timerDisplay) return;
    
    // Calculate elapsed time
    const now = new Date();
    const elapsedSeconds = Math.floor((now - attackStartTime) / 1000);
    
    // Format elapsed time as MM:SS
    const elapsedMinutes = Math.floor(elapsedSeconds / 60);
    const remainingSeconds = elapsedSeconds % 60;
    const elapsedFormatted = `${elapsedMinutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
    
    // Format total duration as MM:SS
    const durationMinutes = Math.floor(attackDuration / 60);
    const durationSeconds = attackDuration % 60;
    const durationFormatted = `${durationMinutes.toString().padStart(2, '0')}:${durationSeconds.toString().padStart(2, '0')}`;
    
    // Update display
    timerDisplay.textContent = `${elapsedFormatted} / ${durationFormatted}`;
    
    // Change color to warn when getting close to end
    if (elapsedSeconds >= attackDuration * 0.8) {
        timerDisplay.className = 'display-4 mb-0 text-warning';
    } else {
        timerDisplay.className = 'display-4 mb-0 text-danger';
    }
    
    // Auto-stop timer when duration is reached
    if (elapsedSeconds >= attackDuration) {
        // Just update UI - the backend should handle the actual stopping
        timerDisplay.textContent = `${durationFormatted} / ${durationFormatted}`;
        timerDisplay.className = 'display-4 mb-0 text-success';
        
        // Don't clear the interval as we should keep polling until server confirms it's stopped
    }
}

function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alertContainer');
    
    // Create alert element
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.role = 'alert';
    
    // Add message - support HTML content
    if (message.includes('<') && message.includes('>')) {
        // Message contains HTML
        alert.innerHTML = message;
    } else {
        // Plain text message
        alert.textContent = message;
    }
    
    // Add close button
    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'btn-close';
    closeButton.setAttribute('data-bs-dismiss', 'alert');
    closeButton.setAttribute('aria-label', 'Close');
    
    // Append close button to alert
    alert.appendChild(closeButton);
    
    // Add alert to container
    alertContainer.appendChild(alert);
    
    // Remove alert after longer time (8 seconds) for messages with links/buttons
    const timeout = message.includes('<a ') ? 8000 : 5000;
    setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => alert.remove(), 150);
    }, timeout);
}
