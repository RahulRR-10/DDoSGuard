/**
 * Algorithm Simulations
 * Interactive visualizations of the algorithms used in SentinelDDoS
 */

document.addEventListener('DOMContentLoaded', () => {
  console.log("Algorithm simulation script loaded!");
  
  // Initialize all visualizations when they're available on the page
  if (document.getElementById('sliding-window')) {
    console.log("Initializing sliding window demo");
    initializeSlidingWindow();
  } else {
    console.log("Sliding window element not found");
  }
  
  if (document.getElementById('ip-distribution')) {
    console.log("Initializing entropy demo");
    initializeEntropyDemo();
  } else {
    console.log("IP distribution element not found");
  }
  
  if (document.getElementById('lru-cache-display')) {
    console.log("Initializing LRU cache demo");
    initializeLRUDemo();
  } else {
    console.log("LRU cache display element not found");
  }
  
  if (document.getElementById('ip-graph')) {
    console.log("Initializing graph demo");
    initializeGraphDemo();
  } else {
    console.log("IP graph element not found");
  }
  
  if (document.getElementById('binary-heap-display')) {
    console.log("Initializing heap demo");
    initializeHeapDemo();
  } else {
    console.log("Binary heap display element not found");
  }
});

/**
 * Sliding Window Algorithm Demo
 */
function initializeSlidingWindow() {
  const slidingWindow = document.getElementById('sliding-window');
  const windowCount = document.getElementById('window-count');
  const addEventBtn = document.getElementById('add-event');
  const advanceTimeBtn = document.getElementById('advance-time');
  
  // Keep track of events in the window with their timestamps
  let events = [];
  let currentTime = 0;
  const windowSize = 10; // Time units
  
  // Update the visualization
  function updateWindow() {
    // Clear the window
    slidingWindow.innerHTML = '';
    
    // Remove expired events
    events = events.filter(event => currentTime - event.time < windowSize);
    
    // Create event blocks in the window
    events.forEach(event => {
      const eventBlock = document.createElement('div');
      eventBlock.className = 'event-block';
      eventBlock.style.width = '20px';
      eventBlock.style.height = '20px';
      eventBlock.style.margin = '2px';
      eventBlock.style.backgroundColor = `rgba(0, 123, 255, ${1 - ((currentTime - event.time) / windowSize)})`;
      eventBlock.title = `Event at time ${event.time}`;
      slidingWindow.appendChild(eventBlock);
    });
    
    // Update the count display
    windowCount.textContent = events.length;
    
    // Move the window to represent the current time
    slidingWindow.style.transform = `translateX(${currentTime * 5}px)`;
  }
  
  // Add a new event at the current time
  addEventBtn.addEventListener('click', () => {
    events.push({ time: currentTime });
    updateWindow();
  });
  
  // Advance the time
  advanceTimeBtn.addEventListener('click', () => {
    currentTime++;
    updateWindow();
  });
  
  // Initial render
  updateWindow();
}

/**
 * Entropy-Based Detection Demo
 */
function initializeEntropyDemo() {
  const patternSelector = document.getElementById('traffic-pattern');
  const calculateBtn = document.getElementById('calculate-entropy');
  const ipDistribution = document.getElementById('ip-distribution');
  const entropyValue = document.getElementById('entropy-value');
  const anomalyScore = document.getElementById('anomaly-score');
  const entropyBar = document.getElementById('entropy-bar');
  const entropyInterpretation = document.getElementById('entropy-interpretation');
  
  // Generate IP distributions based on pattern
  function generateDistribution(pattern) {
    // Clear previous distribution
    ipDistribution.innerHTML = '';
    
    const ipCounts = {};
    const totalIPs = 100;
    
    if (pattern === 'normal') {
      // Generate diverse IP distribution (many IPs with few counts each)
      for (let i = 0; i < totalIPs; i++) {
        const ip = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    } else if (pattern === 'attack') {
      // Generate concentrated IP distribution (few IPs with many counts)
      const attackIPs = 5;
      for (let i = 0; i < totalIPs; i++) {
        let ip;
        if (Math.random() < 0.8) {
          // 80% chance of being an attacker IP
          ip = `10.0.0.${Math.floor(Math.random() * attackIPs) + 1}`;
        } else {
          // 20% chance of being a random IP
          ip = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        }
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    } else if (pattern === 'mixed') {
      // Mixed pattern (some concentration but also diverse)
      for (let i = 0; i < totalIPs; i++) {
        let ip;
        if (Math.random() < 0.4) {
          // 40% chance of being from a small set
          ip = `10.0.0.${Math.floor(Math.random() * 20) + 1}`;
        } else {
          // 60% chance of being a random IP
          ip = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        }
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    }
    
    // Display the distribution visually
    const ips = Object.keys(ipCounts);
    ips.sort((a, b) => ipCounts[b] - ipCounts[a]);
    
    for (const ip of ips.slice(0, 20)) { // Show top 20 IPs
      const ipBlock = document.createElement('div');
      ipBlock.style.display = 'inline-block';
      ipBlock.style.width = `${ipCounts[ip] * 2}px`;
      ipBlock.style.height = '10px';
      ipBlock.style.margin = '1px';
      ipBlock.style.backgroundColor = 'rgba(23, 162, 184, 0.8)';
      ipBlock.title = `${ip}: ${ipCounts[ip]} requests`;
      ipDistribution.appendChild(ipBlock);
    }
    
    return ipCounts;
  }
  
  // Calculate Shannon entropy of the distribution
  function calculateEntropy(ipCounts) {
    const total = Object.values(ipCounts).reduce((sum, count) => sum + count, 0);
    let entropy = 0;
    
    for (const count of Object.values(ipCounts)) {
      const probability = count / total;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
  }
  
  // Update entropy display and interpretations
  function updateEntropy(entropy) {
    // The maximum entropy depends on the number of unique IPs
    const maxEntropy = Math.log2(Object.keys(ipCounts).length);
    
    // Normalize between 0 and 8 (typical max for IP entropy)
    const normalizedEntropy = Math.min(entropy, 8);
    entropyValue.textContent = entropy.toFixed(2);
    
    // Calculate anomaly score (inverse of normalized entropy)
    const entropyAnomalyScore = 1.0 - (normalizedEntropy / 8.0);
    anomalyScore.textContent = entropyAnomalyScore.toFixed(2);
    
    // Update progress bar
    const percentage = (normalizedEntropy / 8.0) * 100;
    entropyBar.style.width = `${percentage}%`;
    
    // Set color based on anomaly level
    if (entropyAnomalyScore > 0.7) {
      entropyBar.className = 'progress-bar bg-danger';
      entropyInterpretation.textContent = 'Low entropy indicates potential DDoS attack (highly concentrated traffic)';
    } else if (entropyAnomalyScore > 0.4) {
      entropyBar.className = 'progress-bar bg-warning';
      entropyInterpretation.textContent = 'Medium entropy indicates potentially suspicious traffic patterns';
    } else {
      entropyBar.className = 'progress-bar bg-success';
      entropyInterpretation.textContent = 'High entropy indicates normal, diverse traffic patterns';
    }
  }
  
  // Initial distribution
  let ipCounts = generateDistribution('normal');
  
  // Calculate entropy when button is clicked
  calculateBtn.addEventListener('click', () => {
    const pattern = patternSelector.value;
    ipCounts = generateDistribution(pattern);
    const entropy = calculateEntropy(ipCounts);
    updateEntropy(entropy);
  });
  
  // Calculate initial entropy
  const initialEntropy = calculateEntropy(ipCounts);
  updateEntropy(initialEntropy);
}

/**
 * LRU Cache Demo
 */
function initializeLRUDemo() {
  const lruAddBtn = document.getElementById('lru-add');
  const lruGetBtn = document.getElementById('lru-get');
  const lruIpInput = document.getElementById('lru-ip');
  const lruCacheDisplay = document.getElementById('lru-cache-display');
  const lruCapacity = document.getElementById('lru-capacity');
  const lruLog = document.getElementById('lru-log');
  
  // LRU Cache implementation
  class LRUCache {
    constructor(capacity) {
      this.capacity = capacity;
      this.cache = new Map(); // key -> value
      this.order = []; // Most recently used at the end
    }
    
    get(key) {
      if (this.cache.has(key)) {
        // Update order (move to most recently used)
        this.order = this.order.filter(k => k !== key);
        this.order.push(key);
        return this.cache.get(key);
      }
      return -1;
    }
    
    put(key, value) {
      // If already exists, remove from order
      if (this.cache.has(key)) {
        this.order = this.order.filter(k => k !== key);
      }
      
      // Add to cache and order
      this.cache.set(key, value);
      this.order.push(key);
      
      // Evict least recently used if over capacity
      if (this.order.length > this.capacity) {
        const lru = this.order.shift();
        this.cache.delete(lru);
        return lru; // Return the evicted key
      }
      
      return null; // No eviction
    }
    
    getAll() {
      return this.order.map(key => ({ key, value: this.cache.get(key) }));
    }
  }
  
  // Create the cache with specified capacity
  const capacity = 5;
  const cache = new LRUCache(capacity);
  lruCapacity.textContent = capacity;
  
  // Update the visualization
  function updateCache() {
    lruCacheDisplay.innerHTML = '';
    
    const items = cache.getAll();
    for (let i = 0; i < items.length; i++) {
      const { key, value } = items[i];
      
      const cacheItem = document.createElement('div');
      cacheItem.className = 'cache-item p-2 m-1 border rounded';
      cacheItem.style.backgroundColor = i === items.length - 1 ? 'rgba(23, 162, 184, 0.3)' : 'rgba(33, 37, 41, 0.5)';
      
      const keyElement = document.createElement('div');
      keyElement.className = 'fw-bold';
      keyElement.textContent = key;
      
      const valueElement = document.createElement('div');
      valueElement.className = 'small';
      valueElement.textContent = `Value: ${value}`;
      
      const orderElement = document.createElement('div');
      orderElement.className = 'small text-muted';
      orderElement.textContent = i === 0 ? 'LRU' : i === items.length - 1 ? 'MRU' : '';
      
      cacheItem.appendChild(keyElement);
      cacheItem.appendChild(valueElement);
      cacheItem.appendChild(orderElement);
      
      lruCacheDisplay.appendChild(cacheItem);
    }
  }
  
  // Add an item to the cache
  lruAddBtn.addEventListener('click', () => {
    const ip = lruIpInput.value;
    const value = Math.floor(Math.random() * 100); // Random value for demo purposes
    
    const evicted = cache.put(ip, value);
    
    if (evicted) {
      logAction(`Added "${ip}" to cache. Evicted "${evicted}" (LRU).`);
    } else {
      logAction(`Added "${ip}" to cache.`);
    }
    
    updateCache();
  });
  
  // Get an item from the cache
  lruGetBtn.addEventListener('click', () => {
    const ip = lruIpInput.value;
    const value = cache.get(ip);
    
    if (value !== -1) {
      logAction(`Retrieved "${ip}" from cache. Value: ${value}`);
    } else {
      logAction(`Cache miss: "${ip}" not found.`);
    }
    
    updateCache();
  });
  
  // Log an action
  function logAction(message) {
    const logItem = document.createElement('div');
    logItem.textContent = message;
    lruLog.prepend(logItem);
    
    // Trim log to last 5 messages
    while (lruLog.children.length > 5) {
      lruLog.removeChild(lruLog.lastChild);
    }
  }
  
  // Initial render
  updateCache();
}

/**
 * Network Graph Demo
 */
function initializeGraphDemo() {
  const addConnectionBtn = document.getElementById('add-connection');
  const sourceIpInput = document.getElementById('source-ip');
  const targetIpInput = document.getElementById('target-ip');
  const addLegitimateBtn = document.getElementById('add-legitimate');
  const addDdosBtn = document.getElementById('add-ddos');
  const ipGraph = document.getElementById('ip-graph');
  
  // Graph data structure
  const nodes = new Map(); // IP -> { connections: {} }
  const edges = []; // [{source, target, weight}]
  
  // Simple graph layout algorithm
  function updateGraph() {
    // Clear graph
    ipGraph.innerHTML = '';
    
    // Create SVG
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    svg.setAttribute('viewBox', '0 0 500 200');
    
    // Position nodes in a circle
    const nodeElements = [];
    const nodeRadius = 15;
    const centerX = 250;
    const centerY = 100;
    const radius = 80;
    
    // Create edges first (so they're behind nodes)
    edges.forEach(edge => {
      const svgEdge = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      svgEdge.setAttribute('stroke', 'rgba(255, 255, 255, 0.3)');
      svgEdge.setAttribute('stroke-width', Math.min(5, Math.max(1, edge.weight)));
      
      // Will set coordinates after nodes are positioned
      edge.element = svgEdge;
      svg.appendChild(svgEdge);
    });
    
    // Create and position nodes
    let i = 0;
    for (const [ip, node] of nodes.entries()) {
      const angle = (i / nodes.size) * 2 * Math.PI;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      
      // Store position for edge connection
      node.x = x;
      node.y = y;
      
      // Create node circle
      const svgNode = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      svgNode.setAttribute('cx', x);
      svgNode.setAttribute('cy', y);
      svgNode.setAttribute('r', nodeRadius);
      svgNode.setAttribute('fill', ip.startsWith('10.') ? 'rgba(220, 53, 69, 0.7)' : 'rgba(40, 167, 69, 0.7)');
      svgNode.setAttribute('stroke', 'white');
      svgNode.setAttribute('stroke-width', '1');
      
      // Tooltip
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = ip;
      svgNode.appendChild(title);
      
      svg.appendChild(svgNode);
      
      // Create label
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', x);
      label.setAttribute('y', y + nodeRadius + 15);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('fill', 'white');
      label.setAttribute('font-size', '10');
      label.textContent = shortenIP(ip);
      
      svg.appendChild(label);
      
      nodeElements.push(svgNode);
      i++;
    }
    
    // Update edge positions
    edges.forEach(edge => {
      const sourceNode = nodes.get(edge.source);
      const targetNode = nodes.get(edge.target);
      
      if (sourceNode && targetNode) {
        edge.element.setAttribute('x1', sourceNode.x);
        edge.element.setAttribute('y1', sourceNode.y);
        edge.element.setAttribute('x2', targetNode.x);
        edge.element.setAttribute('y2', targetNode.y);
      }
    });
    
    ipGraph.appendChild(svg);
  }
  
  // Helper to shorten IP for display
  function shortenIP(ip) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[2]}.${parts[3]}`;
    }
    return ip;
  }
  
  // Add a connection between two IPs
  function addConnection(sourceIp, targetIp) {
    // Add nodes if they don't exist
    if (!nodes.has(sourceIp)) {
      nodes.set(sourceIp, { connections: {} });
    }
    if (!nodes.has(targetIp)) {
      nodes.set(targetIp, { connections: {} });
    }
    
    // Add or update connection
    const sourceNode = nodes.get(sourceIp);
    sourceNode.connections[targetIp] = (sourceNode.connections[targetIp] || 0) + 1;
    
    // Update or add edge
    let edge = edges.find(e => e.source === sourceIp && e.target === targetIp);
    if (edge) {
      edge.weight++;
    } else {
      edges.push({ source: sourceIp, target: targetIp, weight: 1 });
    }
    
    updateGraph();
  }
  
  // Add a connection when button is clicked
  addConnectionBtn.addEventListener('click', () => {
    const sourceIp = sourceIpInput.value;
    const targetIp = targetIpInput.value;
    
    if (sourceIp && targetIp) {
      addConnection(sourceIp, targetIp);
    }
  });
  
  // Simulate legitimate traffic pattern
  addLegitimateBtn.addEventListener('click', () => {
    // Clear existing graph
    nodes.clear();
    edges.length = 0;
    
    // Generate diverse connections (many sources to many targets)
    for (let i = 0; i < 10; i++) {
      const sourceIp = `192.168.1.${10 + i}`;
      
      // Each source connects to 2-3 different targets
      const numTargets = 2 + Math.floor(Math.random() * 2);
      for (let j = 0; j < numTargets; j++) {
        const targetIp = `192.168.2.${10 + Math.floor(Math.random() * 10)}`;
        addConnection(sourceIp, targetIp);
      }
    }
  });
  
  // Simulate DDoS attack pattern
  addDdosBtn.addEventListener('click', () => {
    // Clear existing graph
    nodes.clear();
    edges.length = 0;
    
    // Add a few legitimate connections
    for (let i = 0; i < 3; i++) {
      const sourceIp = `192.168.1.${10 + i}`;
      const targetIp = `192.168.2.${10 + i}`;
      addConnection(sourceIp, targetIp);
    }
    
    // Generate attack pattern (many sources to one target)
    const targetIp = '192.168.2.100';
    for (let i = 0; i < 8; i++) {
      const sourceIp = `10.0.0.${i + 1}`;
      
      // Each attacker makes multiple connections to the target
      const numConnections = 2 + Math.floor(Math.random() * 3);
      for (let j = 0; j < numConnections; j++) {
        addConnection(sourceIp, targetIp);
      }
    }
  });
  
  // Initial empty graph
  updateGraph();
}

/**
 * Priority Queue (Min Heap) Demo
 */
function initializeHeapDemo() {
  const heapAddBtn = document.getElementById('heap-add');
  const heapPopBtn = document.getElementById('heap-pop');
  const heapIpInput = document.getElementById('heap-ip');
  const heapScoreInput = document.getElementById('heap-score');
  const heapDisplay = document.getElementById('binary-heap-display');
  const heapLog = document.getElementById('heap-log');
  
  // Max-heap implementation for threat prioritization
  class MaxHeap {
    constructor() {
      this.heap = [];
    }
    
    // Get parent index
    getParentIndex(i) {
      return Math.floor((i - 1) / 2);
    }
    
    // Get left child index
    getLeftChildIndex(i) {
      return 2 * i + 1;
    }
    
    // Get right child index
    getRightChildIndex(i) {
      return 2 * i + 2;
    }
    
    // Swap elements at indices i and j
    swap(i, j) {
      [this.heap[i], this.heap[j]] = [this.heap[j], this.heap[i]];
    }
    
    // Insert a new element
    insert(item) {
      // Add element to the end
      this.heap.push(item);
      
      // Fix the max heap property if violated (sift up)
      this.siftUp(this.heap.length - 1);
      
      return this.heap.length;
    }
    
    // Sift up to maintain heap property
    siftUp(i) {
      let currentIndex = i;
      let parentIndex = this.getParentIndex(currentIndex);
      
      // While not at root and parent is LESS than current (MAX heap)
      while (
        currentIndex > 0 && 
        this.heap[parentIndex].score < this.heap[currentIndex].score
      ) {
        // Swap with parent
        this.swap(parentIndex, currentIndex);
        
        // Move up
        currentIndex = parentIndex;
        parentIndex = this.getParentIndex(currentIndex);
      }
    }
    
    // Extract the maximum element
    extractMax() {
      if (this.heap.length === 0) return null;
      
      const max = this.heap[0];
      const last = this.heap.pop();
      
      if (this.heap.length > 0) {
        // Move the last element to the root
        this.heap[0] = last;
        
        // Restore heap property (sift down)
        this.siftDown(0);
      }
      
      return max;
    }
    
    // Sift down to maintain heap property
    siftDown(i) {
      let currentIndex = i;
      let maxIndex = i;
      const heapSize = this.heap.length;
      
      while (true) {
        const leftChildIndex = this.getLeftChildIndex(currentIndex);
        const rightChildIndex = this.getRightChildIndex(currentIndex);
        
        // Check if left child is LARGER (MAX heap)
        if (
          leftChildIndex < heapSize && 
          this.heap[leftChildIndex].score > this.heap[maxIndex].score
        ) {
          maxIndex = leftChildIndex;
        }
        
        // Check if right child is LARGER (MAX heap)
        if (
          rightChildIndex < heapSize && 
          this.heap[rightChildIndex].score > this.heap[maxIndex].score
        ) {
          maxIndex = rightChildIndex;
        }
        
        // If no change, heap property is satisfied
        if (maxIndex === currentIndex) break;
        
        // Swap with larger child
        this.swap(currentIndex, maxIndex);
        currentIndex = maxIndex;
      }
    }
    
    // Get the entire heap array
    getHeap() {
      return [...this.heap];
    }
  }
  
  // Create the heap
  const heap = new MaxHeap();
  
  // Update visualization
  function updateHeap() {
    heapDisplay.innerHTML = '';
    
    const heapArray = heap.getHeap();
    if (heapArray.length === 0) {
      heapDisplay.innerHTML = '<div class="text-muted">Empty heap</div>';
      return;
    }
    
    // Create a tree-like visualization
    const treeDepth = Math.floor(Math.log2(heapArray.length)) + 1;
    const numLeaves = Math.pow(2, treeDepth - 1);
    const width = numLeaves * 60;
    
    // Create SVG element
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', width);
    svg.setAttribute('height', treeDepth * 60);
    svg.setAttribute('viewBox', `0 0 ${width} ${treeDepth * 60}`);
    
    // Helper to position a node
    function getNodePosition(index, depth) {
      const nodesAtThisLevel = Math.pow(2, depth);
      const horizontalSpacing = width / nodesAtThisLevel;
      const x = horizontalSpacing * (index + 0.5);
      const y = depth * 50 + 20;
      return { x, y };
    }
    
    // Draw edges first (so they're behind nodes)
    for (let i = 0; i < heapArray.length; i++) {
      const depth = Math.floor(Math.log2(i + 1));
      const parent = heap.getParentIndex(i);
      
      if (i > 0) { // Skip root (no parent)
        const parentPos = getNodePosition(parent % Math.pow(2, Math.floor(Math.log2(parent + 1))), Math.floor(Math.log2(parent + 1)));
        const childPos = getNodePosition(i % Math.pow(2, depth), depth);
        
        const edge = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        edge.setAttribute('x1', parentPos.x);
        edge.setAttribute('y1', parentPos.y);
        edge.setAttribute('x2', childPos.x);
        edge.setAttribute('y2', childPos.y);
        edge.setAttribute('stroke', 'rgba(255, 255, 255, 0.3)');
        edge.setAttribute('stroke-width', '1');
        
        svg.appendChild(edge);
      }
    }
    
    // Draw nodes
    for (let i = 0; i < heapArray.length; i++) {
      const depth = Math.floor(Math.log2(i + 1));
      const { x, y } = getNodePosition(i % Math.pow(2, depth), depth);
      
      // Node circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', x);
      circle.setAttribute('cy', y);
      circle.setAttribute('r', 20);
      
      // Color based on threat level
      let color = 'rgba(40, 167, 69, 0.7)'; // Green (low)
      if (heapArray[i].score >= 0.8) {
        color = 'rgba(220, 53, 69, 0.7)'; // Red (severe)
      } else if (heapArray[i].score >= 0.6) {
        color = 'rgba(255, 193, 7, 0.7)'; // Yellow (medium)
      } else if (heapArray[i].score >= 0.4) {
        color = 'rgba(23, 162, 184, 0.7)'; // Blue (light)
      }
      
      circle.setAttribute('fill', color);
      circle.setAttribute('stroke', 'white');
      circle.setAttribute('stroke-width', '1');
      
      // Score text
      const scoreText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      scoreText.setAttribute('x', x);
      scoreText.setAttribute('y', y + 4);
      scoreText.setAttribute('text-anchor', 'middle');
      scoreText.setAttribute('fill', 'white');
      scoreText.setAttribute('font-size', '12');
      scoreText.textContent = heapArray[i].score.toFixed(1);
      
      // IP text (shortened)
      const ipText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      ipText.setAttribute('x', x);
      ipText.setAttribute('y', y + 24);
      ipText.setAttribute('text-anchor', 'middle');
      ipText.setAttribute('fill', 'white');
      ipText.setAttribute('font-size', '8');
      ipText.textContent = heapArray[i].ip.split('.').slice(-1)[0];
      
      svg.appendChild(circle);
      svg.appendChild(scoreText);
      svg.appendChild(ipText);
    }
    
    heapDisplay.appendChild(svg);
  }
  
  // Add a threat to the heap
  heapAddBtn.addEventListener('click', () => {
    const ip = heapIpInput.value;
    const score = parseFloat(heapScoreInput.value);
    
    if (ip && !isNaN(score)) {
      heap.insert({ ip, score });
      
      // Log the action
      let action = 'Added';
      let level = 'below threshold';
      
      if (score >= 0.8) {
        level = 'SEVERE (block)';
      } else if (score >= 0.6) {
        level = 'MEDIUM (challenge)';
      } else if (score >= 0.4) {
        level = 'LIGHT (rate limit)';
      }
      
      logHeapAction(`${action} IP ${ip} with threat score ${score.toFixed(1)} (${level})`);
      
      updateHeap();
    }
  });
  
  // Extract the highest threat
  heapPopBtn.addEventListener('click', () => {
    const max = heap.extractMax();
    
    if (max) {
      // Log the action
      let level = 'below threshold';
      if (max.score >= 0.8) {
        level = 'SEVERE (block)';
      } else if (max.score >= 0.6) {
        level = 'MEDIUM (challenge)';
      } else if (max.score >= 0.4) {
        level = 'LIGHT (rate limit)';
      }
      
      logHeapAction(`Mitigated IP ${max.ip} with threat score ${max.score.toFixed(1)} (${level})`);
      
      updateHeap();
    } else {
      logHeapAction('Heap is empty, no threats to mitigate.');
    }
  });
  
  // Log heap actions
  function logHeapAction(message) {
    const logItem = document.createElement('div');
    logItem.textContent = message;
    heapLog.prepend(logItem);
    
    // Trim log to last 4 messages
    while (heapLog.children.length > 4) {
      heapLog.removeChild(heapLog.lastChild);
    }
  }
  
  // Initial render
  updateHeap();
}