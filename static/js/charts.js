// charts.js - Helper functions for chart creation and updates

/**
 * Creates a line chart with the specified configuration
 * 
 * @param {string} elementId - The ID of the canvas element
 * @param {object} config - Chart configuration
 * @returns {Chart} The created chart object
 */
function createLineChart(elementId, config) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    const defaultConfig = {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Data',
                data: [],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderWidth: 1,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    display: true,
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Value'
                    }
                }
            },
            plugins: {
                tooltip: {
                    enabled: true
                },
                legend: {
                    position: 'top'
                }
            }
        }
    };
    
    // Merge configs
    const mergedConfig = {
        ...defaultConfig,
        ...config,
        options: {
            ...defaultConfig.options,
            ...(config.options || {})
        }
    };
    
    return new Chart(ctx, mergedConfig);
}

/**
 * Creates a bar chart with the specified configuration
 * 
 * @param {string} elementId - The ID of the canvas element
 * @param {object} config - Chart configuration
 * @returns {Chart} The created chart object
 */
function createBarChart(elementId, config) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    const defaultConfig = {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Data',
                data: [],
                backgroundColor: 'rgba(54, 162, 235, 0.8)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    };
    
    // Merge configs
    const mergedConfig = {
        ...defaultConfig,
        ...config,
        options: {
            ...defaultConfig.options,
            ...(config.options || {})
        }
    };
    
    return new Chart(ctx, mergedConfig);
}

/**
 * Updates a chart with new data while maintaining a maximum number of points
 * 
 * @param {Chart} chart - The chart to update
 * @param {Array} labels - New labels to add
 * @param {Array} datasets - Arrays of data points to add to each dataset
 * @param {number} maxPoints - Maximum number of points to keep
 */
function updateChartData(chart, labels, datasets, maxPoints = 60) {
    // Add new labels
    chart.data.labels = chart.data.labels.concat(labels);
    
    // Add new data to each dataset
    datasets.forEach((data, i) => {
        if (i < chart.data.datasets.length) {
            chart.data.datasets[i].data = chart.data.datasets[i].data.concat(data);
        }
    });
    
    // Trim to max points
    if (chart.data.labels.length > maxPoints) {
        const excess = chart.data.labels.length - maxPoints;
        chart.data.labels = chart.data.labels.slice(excess);
        
        chart.data.datasets.forEach(dataset => {
            dataset.data = dataset.data.slice(excess);
        });
    }
    
    // Update the chart
    chart.update();
}

/**
 * Creates a gauge chart to visualize a value from 0-1
 * 
 * @param {string} elementId - The ID of the canvas element
 * @param {number} value - The value to display (0-1)
 * @param {string} label - The label for the gauge
 * @returns {Chart} The created chart object
 */
function createGaugeChart(elementId, value, label) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // Determine color based on value
    let color = 'rgba(75, 192, 192, 1)'; // Default teal
    
    if (value >= 0.8) {
        color = 'rgba(255, 99, 132, 1)'; // Red for high values
    } else if (value >= 0.6) {
        color = 'rgba(255, 159, 64, 1)'; // Orange for medium-high values
    } else if (value >= 0.4) {
        color = 'rgba(255, 205, 86, 1)'; // Yellow for medium values
    }
    
    const config = {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, 1 - value],
                backgroundColor: [
                    color,
                    'rgba(200, 200, 200, 0.2)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            circumference: 180,
            rotation: -90,
            cutout: '80%',
            plugins: {
                tooltip: {
                    enabled: false
                },
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: label,
                    position: 'bottom'
                }
            },
            maintainAspectRatio: false
        },
        plugins: [{
            id: 'centerText',
            afterDraw: (chart) => {
                const width = chart.width;
                const height = chart.height;
                const ctx = chart.ctx;
                
                ctx.restore();
                ctx.font = '24px Arial';
                ctx.textBaseline = 'middle';
                ctx.textAlign = 'center';
                ctx.fillStyle = color;
                
                // Format value as percentage
                const text = `${Math.round(value * 100)}%`;
                
                // Position text in center of gauge
                ctx.fillText(text, width / 2, height - 30);
                ctx.save();
            }
        }]
    };
    
    return new Chart(ctx, config);
}

/**
 * Updates a gauge chart with a new value
 * 
 * @param {Chart} chart - The gauge chart to update
 * @param {number} value - The new value (0-1)
 */
function updateGaugeChart(chart, value) {
    // Update data
    chart.data.datasets[0].data = [value, 1 - value];
    
    // Update color based on value
    let color = 'rgba(75, 192, 192, 1)'; // Default teal
    
    if (value >= 0.8) {
        color = 'rgba(255, 99, 132, 1)'; // Red for high values
    } else if (value >= 0.6) {
        color = 'rgba(255, 159, 64, 1)'; // Orange for medium-high values
    } else if (value >= 0.4) {
        color = 'rgba(255, 205, 86, 1)'; // Yellow for medium values
    }
    
    chart.data.datasets[0].backgroundColor[0] = color;
    
    // Update the chart
    chart.update();
}
