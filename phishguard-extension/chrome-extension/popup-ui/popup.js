/**
 * PhishGuard Extension Popup UI
 * Controls the UI interactions for the extension popup
 */

// DOM Elements
const enableToggle = document.getElementById('enable-toggle');
const extensionStatus = document.getElementById('extension-status');
const phishingCount = document.getElementById('phishing-count');
const lastScan = document.getElementById('last-scan');
const scanPageButton = document.getElementById('scan-page');
const viewSettingsButton = document.getElementById('view-settings');
const scanResults = document.getElementById('scan-results');
const scanVerdict = document.getElementById('scan-verdict');
const scanConfidence = document.getElementById('scan-confidence');
const scanFeatures = document.getElementById('scan-features');

// DOM elements for statistics
const statsDashboard = document.getElementById('stats-dashboard');
const totalScans = document.getElementById('total-scans');
const totalPhishing = document.getElementById('total-phishing');
const detectionRate = document.getElementById('detection-rate');
const daysActive = document.getElementById('days-active');
const viewResultsButton = document.getElementById('view-results');
const viewStatsButton = document.getElementById('view-stats');

// DOM elements for feedback
const thumbsUpButton = document.getElementById('thumbs-up');
const thumbsDownButton = document.getElementById('thumbs-down');
const feedbackMessage = document.getElementById('feedback-message');
const feedbackPanel = document.getElementById('feedback-panel');

// Extension state
let extensionState = {
  enabled: true,
  lastScan: null,
  detectionCount: 0
};

// Initialize the popup
document.addEventListener('DOMContentLoaded', async () => {
  console.log("Authentication bypass enabled - using local simulation mode");
  await loadState();
  updateUI();
  
  enableToggle.addEventListener('change', toggleExtension);
  scanPageButton.addEventListener('click', scanCurrentPage);
  viewSettingsButton.addEventListener('click', openSettings);
  viewResultsButton.addEventListener('click', showScanResults);
  viewStatsButton.addEventListener('click', showStatsDashboard);
  thumbsUpButton.addEventListener('click', () => submitUserFeedback(true));
  thumbsDownButton.addEventListener('click', () => submitUserFeedback(false));

  let lastScanResult = null;
  loadStatistics();
  checkAPIHealth();
});

/**
 * Load extension state from storage
 */
async function loadState() {
  try {
    const result = await chrome.storage.local.get(['phishguardState']);
    if (result.phishguardState) {
      extensionState = result.phishguardState;
    }
  } catch (error) {
    console.error('Failed to load state:', error);
  }
}

/**
 * Save extension state to storage
 */
async function saveState() {
  try {
    await chrome.storage.local.set({ phishguardState: extensionState });
  } catch (error) {
    console.error('Failed to save state:', error);
  }
}

/**
 * Update UI elements based on current state
 */
function updateUI() {
  enableToggle.checked = extensionState.enabled;
  extensionStatus.textContent = extensionState.enabled ? 'Active' : 'Inactive';
  extensionStatus.className = extensionState.enabled ? 'status-value active' : 'status-value inactive';
  phishingCount.textContent = extensionState.detectionCount || 0;
  
  if (extensionState.lastScan) {
    const scanDate = new Date(extensionState.lastScan);
    const now = new Date();
    const diffMs = now - scanDate;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) {
      lastScan.textContent = 'Just now';
    } else if (diffMins < 60) {
      lastScan.textContent = `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
    } else {
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) {
        lastScan.textContent = `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
      } else {
        lastScan.textContent = scanDate.toLocaleDateString();
      }
    }
  } else {
    lastScan.textContent = 'Never';
  }
  
  scanPageButton.disabled = !extensionState.enabled;
}

/**
 * Toggle extension enabled/disabled state
 */
async function toggleExtension(event) {
  extensionState.enabled = event.target.checked;
  await saveState();
  updateUI();
}

/**
 * Check API health and update UI accordingly
 */
async function checkAPIHealth() {
  try {
    const healthResult = await window.phishGuardAPI.checkHealth();
    if (healthResult.status === 'online') {
      console.log('API is online:', healthResult);
    } else {
      console.warn('API health check failed:', healthResult);
    }
  } catch (error) {
    console.error('API health check error:', error);
  }
}

/**
 * Scan the current page for phishing indicators (email content only)
 */
async function scanCurrentPage() {
  scanPageButton.textContent = 'Scanning...';
  scanPageButton.disabled = true;
  scanResults.classList.add('hidden');
  
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    const url = currentTab.url;
    console.log('Current URL:', url);
    
    if (!url.startsWith('http')) {
      throw new Error('Can only scan web pages');
    }
    
    // Check if on an email client
    const isEmailClient = url.includes('mail.google.com') || 
                         url.includes('outlook.com') || 
                         (url.includes('yahoo.com') && url.includes('/mail'));
    
    if (!isEmailClient) {
      throw new Error('Please open an email client (Gmail, Outlook, or Yahoo Mail) to scan email content');
    }
    
    // Try getting content via message
    chrome.tabs.sendMessage(currentTab.id, { action: 'getPageContent' }, async (response) => {
      console.log('Content script response:', response);
      let content = '';
      
      if (chrome.runtime.lastError || !response || !response.content) {
        console.log('No content from message, attempting direct extraction');
        content = await new Promise((resolve) => {
          chrome.scripting.executeScript({
            target: { tabId: currentTab.id },
            function: () => {
              return document.querySelector('.a3s.aiL')?.innerText || 
                     document.querySelector('.ii.gt')?.innerText || 
                     document.querySelector('.message')?.innerText || 
                     document.querySelector('.readMessageContent')?.innerText || 
                     document.querySelector('.message-content')?.innerText || '';
            }
          }, (results) => resolve(results?.[0]?.result || ''));
        });
      } else {
        content = response.content;
      }
      
      if (!content) {
        throw new Error('No email content found on this page');
      }
      
      console.log('Extracted email content:', content.substring(0, 100));
      const result = await window.phishGuardAPI.analyzeEmail(content);
      console.log('Email scan result:', result);
      displayResults(result);
    });
  } catch (error) {
    console.error('Scan failed:', error);
    displayError(error.message);
  }
}

/**
 * Display scan results in the UI
 */
function displayResults(result) {
  extensionState.lastScan = new Date().toISOString();
  if (result.prediction === 'phishing') {
    extensionState.detectionCount++;
  }
  saveState();
  
  scanPageButton.textContent = 'Scan Current Page';
  scanPageButton.disabled = false;
  scanResults.classList.remove('hidden');
  
  feedbackPanel.classList.remove('hidden');
  feedbackMessage.classList.add('hidden');
  
  if (result.prediction === 'phishing') {
    scanVerdict.textContent = 'Likely Phishing';
    scanVerdict.className = 'result-value verdict-phishing';
  } else {
    scanVerdict.textContent = 'Likely Safe';
    scanVerdict.className = 'result-value verdict-safe';
  }
  
  const confidence = Math.round(result.confidence * 100);
  scanConfidence.textContent = `${confidence}%`;
  
  // Display email-specific features
  scanFeatures.textContent = 'Email content analysis';
  
  updateUI();
}

/**
 * Display error message
 */
function displayError(message) {
  scanPageButton.textContent = 'Scan Current Page';
  scanPageButton.disabled = false;
  scanResults.classList.remove('hidden');
  scanVerdict.textContent = 'Error';
  scanVerdict.className = 'result-value verdict-phishing';
  scanConfidence.textContent = 'N/A';
  scanFeatures.textContent = message || 'Unknown error';
  updateUI();
}

/**
 * Open settings page
 */
function openSettings() {
  chrome.tabs.create({ url: 'options.html' });
}

// Function to show scan results panel
function showScanResults() {
  scanResults.classList.remove('hidden');
  statsDashboard.classList.add('hidden');
  viewResultsButton.disabled = true;
  viewStatsButton.disabled = false;
}

// Function to show statistics dashboard
function showStatsDashboard() {
  scanResults.classList.add('hidden');
  statsDashboard.classList.remove('hidden');
  viewResultsButton.disabled = false;
  viewStatsButton.disabled = true;
}

// Function to load and display statistics
async function loadStatistics() {
  try {
    const result = await chrome.storage.local.get(['phishguardState', 'phishguardStats']);
    const state = result.phishguardState || {};
    const stats = result.phishguardStats || {};
    
    totalScans.textContent = stats.scansPerformed || 0;
    totalPhishing.textContent = stats.phishingDetected || 0;
    
    if (stats.scansPerformed && stats.scansPerformed > 0) {
      const rate = (stats.phishingDetected / stats.scansPerformed * 100).toFixed(1);
      detectionRate.textContent = `${rate}%`;
    } else {
      detectionRate.textContent = 'N/A';
    }
    
    if (stats.timeInstalled) {
      const installDate = new Date(stats.timeInstalled);
      const now = new Date();
      const diffTime = Math.abs(now - installDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      daysActive.textContent = diffDays;
    } else {
      daysActive.textContent = 'Unknown';
    }
    
    if (window.phishGuardAPI && window.phishGuardAPI.isAuthenticated()) {
      fetchAPIStatistics();
    }
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

// Function to fetch API statistics
async function fetchAPIStatistics() {
  try {
    const result = await chrome.storage.local.get(['authToken']);
    const authToken = result.authToken;
    
    if (!authToken) {
      console.warn('No auth token available');
      return;
    }
    
    const apiEndpoint = (await chrome.storage.local.get(['phishguardConfig'])).phishguardConfig?.apiUrl || 'https://api.phishguard.example.com/v1';
    
    const response = await fetch(`${apiEndpoint}/stats`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (response.ok) {
      const apiStats = await response.json();
      console.log('API statistics:', apiStats);
    }
  } catch (error) {
    console.error('Error fetching API statistics:', error);
  }
}

// Function to submit user feedback
async function submitUserFeedback(isCorrect) {
  try {
    if (!lastScanResult || !lastScanResult.scan_id) {
      console.error('No scan result to submit feedback for');
      return;
    }
    
    thumbsUpButton.disabled = true;
    thumbsDownButton.disabled = true;
    
    await window.phishGuardAPI.submitFeedback(lastScanResult.scan_id, isCorrect);
    
    feedbackMessage.textContent = 'Thank you for your feedback!';
    feedbackMessage.classList.remove('hidden');
    
    thumbsUpButton.disabled = false;
    thumbsDownButton.disabled = false;
    
    console.log('Feedback submitted successfully');
  } catch (error) {
    console.error('Error submitting feedback:', error);
    feedbackMessage.textContent = 'Error submitting feedback. Please try again.';
    feedbackMessage.classList.remove('hidden');
    thumbsUpButton.disabled = false;
    thumbsDownButton.disabled = false;
  }
}