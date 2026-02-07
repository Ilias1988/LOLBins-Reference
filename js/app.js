// LOLBins Reference - Application Logic
// Version 2.0 with Dynamic Counting & Payload Builder

// State
let currentOS = 'windows';
let currentCategory = 'all';
let currentView = 'grid';
let searchQuery = '';

// Payload Builder Config
let payloadConfig = {
    lhost: '10.10.14.5',
    lport: '4444'
};

// Original commands storage (before replacement)
let originalData = {
    windows: [],
    linux: []
};

// DOM Elements
const searchInput = document.getElementById('searchInput');
const clearSearch = document.getElementById('clearSearch');
const cardsContainer = document.getElementById('cardsContainer');
const noResults = document.getElementById('noResults');
const resultsCount = document.getElementById('resultsCount');
const windowsCount = document.getElementById('windowsCount');
const linuxCount = document.getElementById('linuxCount');
const modalOverlay = document.getElementById('modalOverlay');
const modalBody = document.getElementById('modalBody');
const modalTitle = document.getElementById('modalTitle');
const modalIcon = document.getElementById('modalIcon');
const modalClose = document.getElementById('modalClose');
const toast = document.getElementById('toast');
const toastMessage = document.getElementById('toastMessage');
const lhostInput = document.getElementById('lhostInput');
const lportInput = document.getElementById('lportInput');
const applyConfigBtn = document.getElementById('applyConfig');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    // Store original data for replacement
    storeOriginalData();
    
    // Set counts
    windowsCount.textContent = LOLBinsData.windows.length;
    linuxCount.textContent = LOLBinsData.linux.length;
    
    // Calculate and display category counts
    updateCategoryCounts();
    
    // Apply initial payload config
    applyPayloadConfig();
    
    // Render initial data
    renderCards();
    
    // Setup event listeners
    setupEventListeners();
}

// Store original commands before any modification
function storeOriginalData() {
    // Deep clone the data
    originalData.windows = JSON.parse(JSON.stringify(LOLBinsData.windows));
    originalData.linux = JSON.parse(JSON.stringify(LOLBinsData.linux));
}

// Calculate category counts dynamically
function calculateCategoryCounts(os) {
    const data = os === 'windows' ? LOLBinsData.windows : LOLBinsData.linux;
    const counts = {};
    
    data.forEach(item => {
        if (item.categories && Array.isArray(item.categories)) {
            item.categories.forEach(cat => {
                counts[cat] = (counts[cat] || 0) + 1;
            });
        }
    });
    
    return counts;
}

// Update filter buttons with counts
function updateCategoryCounts() {
    // Windows categories
    const windowsCounts = calculateCategoryCounts('windows');
    updateFilterButtons('windowsFilters', windowsCounts);
    
    // Linux categories
    const linuxCounts = calculateCategoryCounts('linux');
    updateFilterButtons('linuxFilters', linuxCounts);
}

function updateFilterButtons(containerId, counts) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const buttons = container.querySelectorAll('.filter-btn');
    buttons.forEach(btn => {
        const category = btn.dataset.category;
        if (category === 'all') {
            // All button shows total
            const total = Object.values(counts).reduce((sum, val) => sum + val, 0);
            // Don't show count for "All" button
        } else {
            const count = counts[category] || 0;
            // Update button text to include count
            const label = getCategoryLabel(category);
            const labelText = label.split(' ').slice(1).join(' '); // Remove emoji
            const emoji = label.split(' ')[0];
            
            if (count > 0) {
                btn.innerHTML = `${emoji} ${labelText} <span class="filter-count">(${count})</span>`;
            } else {
                btn.innerHTML = `${emoji} ${labelText} <span class="filter-count">(0)</span>`;
                btn.style.opacity = '0.5';
            }
        }
    });
}

// Payload Builder Functions
function applyPayloadConfig() {
    payloadConfig.lhost = lhostInput?.value || '10.10.14.5';
    payloadConfig.lport = lportInput?.value || '4444';
    
    // Update all commands with new IP/Port
    replacePayloadPlaceholders();
}

function replacePayloadPlaceholders() {
    // Process Windows data
    LOLBinsData.windows = originalData.windows.map(item => {
        return {
            ...item,
            commands: item.commands.map(cmd => ({
                ...cmd,
                code: sanitizeCommand(cmd.code, payloadConfig.lhost, payloadConfig.lport)
            }))
        };
    });
    
    // Process Linux data
    LOLBinsData.linux = originalData.linux.map(item => {
        return {
            ...item,
            commands: item.commands.map(cmd => ({
                ...cmd,
                code: sanitizeCommand(cmd.code, payloadConfig.lhost, payloadConfig.lport)
            }))
        };
    });
}

/**
 * sanitizeCommand - Replace ALL IPs and Ports in a command with user values
 * 
 * Strategy:
 * 1. First replace IP:PORT combos (e.g. 192.168.1.9:66 → userIP:userPort)
 * 2. Then replace IP/PORT combos (e.g. /dev/tcp/192.168.1.10/54 → /dev/tcp/userIP/userPort)
 * 3. Then replace standalone private/local IPs
 * 4. Then replace text placeholders ({IP}, LHOST, RHOST, etc.)
 * 5. Then replace standalone port placeholders
 */
function sanitizeCommand(cmd, userIP, userPort) {
    if (!cmd) return '';
    let result = cmd;
    
    // === PHASE 1: Replace IP:PORT combos (colon separator) ===
    // Matches: 192.168.x.x:PORT, 10.x.x.x:PORT, 172.16-31.x.x:PORT, 127.0.0.1:PORT, 0.0.0.0:PORT
    result = result.replace(
        /((?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}):(\d{1,5})/g,
        userIP + ':' + userPort
    );
    result = result.replace(
        /(127\.0\.0\.1|0\.0\.0\.0):(\d{1,5})/g,
        userIP + ':' + userPort
    );
    
    // === PHASE 2: Replace IP/PORT combos (slash separator, e.g. /dev/tcp/IP/PORT) ===
    result = result.replace(
        /(\/dev\/tcp\/)((?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\/(\d{1,5})/g,
        '$1' + userIP + '/' + userPort
    );
    result = result.replace(
        /(\/dev\/tcp\/)(127\.0\.0\.1|0\.0\.0\.0)\/(\d{1,5})/g,
        '$1' + userIP + '/' + userPort
    );
    
    // === PHASE 3: Replace standalone private/local IPs ===
    result = result.replace(/192\.168\.\d{1,3}\.\d{1,3}/g, userIP);
    result = result.replace(/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, userIP);
    result = result.replace(/172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/g, userIP);
    result = result.replace(/127\.0\.0\.1/g, userIP);
    result = result.replace(/0\.0\.0\.0/g, userIP);
    
    // === PHASE 4: Replace text placeholders (IP) ===
    result = result.replace(/ATTACKER_IP/gi, userIP);
    result = result.replace(/<IP>/gi, userIP);
    result = result.replace(/<LHOST>/gi, userIP);
    result = result.replace(/<RHOST>/gi, userIP);
    result = result.replace(/\{IP\}/gi, userIP);
    result = result.replace(/\{LHOST\}/gi, userIP);
    result = result.replace(/\{RHOST\}/gi, userIP);
    result = result.replace(/\$LHOST\b/g, userIP);
    result = result.replace(/\$RHOST\b/g, userIP);
    result = result.replace(/attacker\.com/gi, userIP);
    result = result.replace(/evil\.com/gi, userIP);
    result = result.replace(/example\.com/gi, userIP);
    
    // === PHASE 5: Replace text placeholders (Port) ===
    result = result.replace(/<PORT>/gi, userPort);
    result = result.replace(/<LPORT>/gi, userPort);
    result = result.replace(/<RPORT>/gi, userPort);
    result = result.replace(/\{PORT\}/gi, userPort);
    result = result.replace(/\{LPORT\}/gi, userPort);
    result = result.replace(/\{RPORT\}/gi, userPort);
    result = result.replace(/\$LPORT\b/g, userPort);
    result = result.replace(/\$RPORT\b/g, userPort);
    
    // === PHASE 6: Replace common hardcoded ports (standalone, word boundary) ===
    result = result.replace(/\b4444\b/g, userPort);
    result = result.replace(/\b1337\b/g, userPort);
    result = result.replace(/\b9001\b/g, userPort);
    
    return result;
}

function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const os = tab.dataset.os;
            switchOS(os);
        });
    });
    
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const category = btn.dataset.category;
            setCategory(category);
        });
    });
    
    // View toggle
    document.querySelectorAll('.view-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            setView(view);
        });
    });
    
    // Search
    searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.toLowerCase();
        renderCards();
    });
    
    clearSearch.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        renderCards();
        searchInput.focus();
    });
    
    // Payload Builder inputs - real-time update
    if (lhostInput) {
        lhostInput.addEventListener('input', debounce(() => {
            applyPayloadConfig();
            renderCards();
            showToast('LHOST updated!');
        }, 500));
    }
    
    if (lportInput) {
        lportInput.addEventListener('input', debounce(() => {
            applyPayloadConfig();
            renderCards();
            showToast('LPORT updated!');
        }, 500));
    }
    
    // Apply button
    if (applyConfigBtn) {
        applyConfigBtn.addEventListener('click', () => {
            applyPayloadConfig();
            renderCards();
            showToast(`Applied: ${payloadConfig.lhost}:${payloadConfig.lport}`);
        });
    }
    
    // Modal close
    modalClose.addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) {
            closeModal();
        }
    });
    
    // Resources Modal
    const resourcesBtn = document.getElementById('resourcesBtn');
    const resourcesModalOverlay = document.getElementById('resourcesModalOverlay');
    const resourcesModalClose = document.getElementById('resourcesModalClose');
    
    if (resourcesBtn && resourcesModalOverlay) {
        resourcesBtn.addEventListener('click', () => {
            resourcesModalOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';
        });
        
        resourcesModalClose.addEventListener('click', () => {
            resourcesModalOverlay.classList.remove('active');
            document.body.style.overflow = '';
        });
        
        resourcesModalOverlay.addEventListener('click', (e) => {
            if (e.target === resourcesModalOverlay) {
                resourcesModalOverlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            if (resourcesModalOverlay) {
                resourcesModalOverlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        }
        if (e.key === '/' && document.activeElement !== searchInput) {
            e.preventDefault();
            searchInput.focus();
        }
    });
}

// Debounce utility for real-time input
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function switchOS(os) {
    currentOS = os;
    currentCategory = 'all'; // Reset category when switching OS
    
    // Update tab UI
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.os === os);
    });
    
    // Switch filter containers
    document.getElementById('windowsFilters').style.display = os === 'windows' ? 'flex' : 'none';
    document.getElementById('linuxFilters').style.display = os === 'linux' ? 'flex' : 'none';
    
    // Reset category filter UI
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.category === 'all');
    });
    
    renderCards();
}

function setCategory(category) {
    currentCategory = category;
    
    // Update filter UI - only for current OS filters
    const currentFilters = currentOS === 'windows' ? 'windowsFilters' : 'linuxFilters';
    document.querySelectorAll(`#${currentFilters} .filter-btn`).forEach(btn => {
        btn.classList.toggle('active', btn.dataset.category === category);
    });
    
    renderCards();
}

function setView(view) {
    currentView = view;
    
    // Update view toggle UI
    document.querySelectorAll('.view-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });
    
    // Update container class
    cardsContainer.classList.toggle('list-view', view === 'list');
}

function getFilteredData() {
    let data = currentOS === 'windows' ? LOLBinsData.windows : LOLBinsData.linux;
    
    // Filter by category
    if (currentCategory !== 'all') {
        data = data.filter(item => item.categories && item.categories.includes(currentCategory));
    }
    
    // Filter by search query
    if (searchQuery) {
        data = data.filter(item => {
            const searchableText = [
                item.name,
                item.description,
                ...(item.categories || []),
                item.mitre?.technique || '',
                item.mitre?.name || ''
            ].join(' ').toLowerCase();
            
            return searchableText.includes(searchQuery);
        });
    }
    
    return data;
}

function renderCards() {
    const data = getFilteredData();
    
    // Update results count
    resultsCount.textContent = `Showing ${data.length} ${data.length === 1 ? 'binary' : 'binaries'}`;
    
    // Show/hide no results message
    if (data.length === 0) {
        cardsContainer.innerHTML = '';
        noResults.style.display = 'block';
        return;
    }
    
    noResults.style.display = 'none';
    
    // Generate cards HTML
    const cardsHTML = data.map(item => createCardHTML(item)).join('');
    cardsContainer.innerHTML = cardsHTML;
    
    // Add click listeners to cards
    document.querySelectorAll('.card').forEach((card, index) => {
        card.addEventListener('click', () => {
            openModal(data[index]);
        });
    });
}

function createCardHTML(item) {
    const osIcon = currentOS === 'windows' ? '🪟' : '🐧';
    const categories = item.categories || [];
    const tagsHTML = categories.map(cat => 
        `<span class="tag ${cat}">${getCategoryLabel(cat)}</span>`
    ).join('');
    
    const mitreTechnique = item.mitre?.technique || 'N/A';
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">${item.name}</h3>
                <span class="card-os-badge">${osIcon}</span>
            </div>
            <p class="card-description">${item.description || 'No description available'}</p>
            <div class="card-tags">
                ${tagsHTML}
            </div>
            <div class="card-mitre">
                <span class="mitre-label">MITRE:</span>
                <span class="mitre-id">${mitreTechnique}</span>
            </div>
        </div>
    `;
}

function getCategoryLabel(category) {
    const labels = {
        // Linux Categories
        'sudo': '🔓 Sudo',
        'suid': '⚡ SUID',
        'shell': '💀 Shell',
        'capabilities': '🎯 Caps',
        'file-read': '📖 Read',
        'file-write': '✏️ Write',
        'reverse-shell': '🔄 RevShell',
        'bind-shell': '🔗 Bind',
        'file-upload': '📤 Upload',
        'file-download': '📥 Download',
        'library-load': '📚 Library',
        'limited-suid': '⚠️ Limited',
        // Windows Categories
        'download': '📥 Download',
        'execute': '⚡ Execute',
        'uac-bypass': '🛡️ UAC',
        'awl-bypass': '🚫 AWL',
        'compile': '🔨 Compile',
        'encode': '🔐 Encode',
        'recon': '🔍 Recon',
        'ads': '📎 ADS',
        'copy': '📋 Copy'
    };
    return labels[category] || category;
}

function openModal(item) {
    const osIcon = currentOS === 'windows' ? '🪟' : '🐧';
    modalIcon.textContent = osIcon;
    modalTitle.textContent = item.name;
    
    // Generate modal content
    const categories = item.categories || [];
    const tagsHTML = categories.map(cat => 
        `<span class="tag ${cat}">${getCategoryLabel(cat)}</span>`
    ).join('');
    
    const commands = item.commands || [];
    const commandsHTML = commands.map(cmd => {
        const escapedCode = escapeHtml(cmd.code);
        return `
        <div class="command-block">
            <div class="command-header">
                <span class="command-label">${cmd.label || 'Command'}</span>
                <button class="copy-btn" onclick="copyToClipboard(this, \`${escapedCode.replace(/`/g, '\\`')}\`)">
                    📋 Copy
                </button>
            </div>
            <pre class="command-code">${escapedCode}</pre>
        </div>
    `}).join('');
    
    const detection = item.detection || [];
    const detectionHTML = detection.map(d => `<li>${d}</li>`).join('') || '<li>No detection information available</li>';
    
    const references = item.references || [];
    const referencesHTML = references.map(ref => `
        <a href="${ref.url}" target="_blank" rel="noopener noreferrer" class="external-link">
            🔗 ${ref.name}
        </a>
    `).join('');
    
    const mitre = item.mitre || { technique: 'N/A', name: 'Unknown', url: '#' };
    
    modalBody.innerHTML = `
        <div class="modal-section">
            <h4 class="modal-section-title">📝 Description</h4>
            <p class="modal-description">${item.description || 'No description available'}</p>
        </div>
        
        <div class="modal-section">
            <h4 class="modal-section-title">🏷️ Categories</h4>
            <div class="modal-tags">
                ${tagsHTML || '<span class="tag">uncategorized</span>'}
            </div>
        </div>
        
        <div class="modal-section">
            <h4 class="modal-section-title">💻 Commands</h4>
            <div class="payload-notice">
                <span>🎯 Commands use LHOST: <strong>${payloadConfig.lhost}</strong> | LPORT: <strong>${payloadConfig.lport}</strong></span>
            </div>
            ${commandsHTML || '<p class="text-muted">No commands available</p>'}
        </div>
        
        <div class="modal-section">
            <h4 class="modal-section-title">🎯 MITRE ATT&CK</h4>
            <div class="mitre-info">
                <div class="mitre-item">
                    <span class="mitre-item-label">Technique ID</span>
                    <span class="mitre-item-value">
                        <a href="${mitre.url}" target="_blank" rel="noopener noreferrer">
                            ${mitre.technique}
                        </a>
                    </span>
                </div>
                <div class="mitre-item">
                    <span class="mitre-item-label">Technique Name</span>
                    <span class="mitre-item-value">${mitre.name}</span>
                </div>
            </div>
        </div>
        
        <div class="modal-section">
            <h4 class="modal-section-title">🔍 Detection</h4>
            <ul class="detection-list">
                ${detectionHTML}
            </ul>
        </div>
        
        <div class="modal-section">
            <h4 class="modal-section-title">📚 References</h4>
            <div class="external-links">
                ${referencesHTML}
                <a href="${mitre.url}" target="_blank" rel="noopener noreferrer" class="external-link">
                    🔗 MITRE ATT&CK
                </a>
            </div>
        </div>
    `;
    
    modalOverlay.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    modalOverlay.classList.remove('active');
    document.body.style.overflow = '';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(button, text) {
    // Unescape the text
    const unescapedText = text.replace(/\\`/g, '`');
    
    navigator.clipboard.writeText(unescapedText).then(() => {
        showToast('Copied to clipboard!');
        
        // Visual feedback on button
        const originalText = button.innerHTML;
        button.innerHTML = '✓ Copied!';
        button.style.backgroundColor = 'var(--accent-green)';
        button.style.borderColor = 'var(--accent-green)';
        button.style.color = 'white';
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.style.backgroundColor = '';
            button.style.borderColor = '';
            button.style.color = '';
        }, 1500);
    }).catch(err => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = unescapedText;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        
        try {
            document.execCommand('copy');
            showToast('Copied to clipboard!');
        } catch (e) {
            showToast('Failed to copy', true);
        }
        
        document.body.removeChild(textarea);
    });
}

function showToast(message, isError = false) {
    toastMessage.textContent = message;
    toast.style.backgroundColor = isError ? 'var(--accent-red)' : 'var(--accent-green)';
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2000);
}

// Make copyToClipboard available globally for onclick handlers
window.copyToClipboard = copyToClipboard;
