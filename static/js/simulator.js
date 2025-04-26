// Simulator.js - Handles the attack simulation functionality

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
    
    // Check if an attack is currently running
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
        updateSimulationStatus(true, attackType, duration, intensity, distribution);
        
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
    // Create a status check function
    // For now, we'll just assume no attack is running initially
    // In a real implementation, you would fetch the current status from the server
    
    fetch('/api/simulate/status')
        .then(response => response.json())
        .then(data => {
            if (data.is_running) {
                updateSimulationStatus(
                    true,
                    data.attack_type,
                    data.duration,
                    data.intensity,
                    data.distribution
                );
            } else {
                updateSimulationStatus(false);
            }
        })
        .catch(error => {
            console.error('Error checking attack status:', error);
        });
}

function updateSimulationStatus(isRunning, attackType = '', duration = 0, intensity = 0, distribution = '') {
    const statusContainer = document.getElementById('attackStatusContainer');
    const statusBadge = document.getElementById('attackStatusBadge');
    const attackForm = document.getElementById('attackForm');
    const startButton = document.getElementById('startAttackBtn');
    const stopButton = document.getElementById('stopAttackBtn');
    const attackDetails = document.getElementById('attackDetails');
    
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
