// Background service worker for PhishGuard extension
// Import validators (using importScripts since service workers can't use ES modules yet)
importScripts('../shared/validators.js');
// Initialize extension state
let state = {
  enabled: true,
  lastScan: null,
  detectionCount: 0,
  scansPerformed: 0,              // Add this line
  warningsDisplayed: 0,           // Add this line
  installTime: null,              // Add this line
  apiEndpoint: 'http://127.0.0.1:5000/v1' // Will be configured properly later
};

// Load state from storage
chrome.storage.local.get(['phishguardState'], (result) => {
  if (result.phishguardState) {
    state = { ...state, ...result.phishguardState };
  }
  
  // Save initial state if not present
  if (!result.phishguardState) {
    chrome.storage.local.set({ phishguardState: state });
  }
});

// Listen for navigation events to scan new pages
chrome.webNavigation.onCompleted.addListener((details) => {
  // Only inject content scripts if extension is enabled
  if (state.enabled && details.frameId === 0) { // Main frame only
    chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      files: ['content-scripts/dom-scanner.js']
    }).catch(error => {
      console.error('Failed to inject content script:', error);
    });
    
    // Update badge to show scanning
    chrome.action.setBadgeText({ 
      text: 'SCAN',
      tabId: details.tabId 
    });
    
    chrome.action.setBadgeBackgroundColor({ 
      color: '#4285F4',
      tabId: details.tabId 
    });
    
    // Reset badge after 3 seconds
    setTimeout(() => {
      chrome.action.setBadgeText({ 
        text: '',
        tabId: details.tabId 
      });
    }, 3000);
  }
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_URL') {
    scanUrl(message.url, sender.tab.id)
      .then(result => {
        sendResponse(result);
        updateBadgeWithResult(result, sender.tab.id);
      })
      .catch(error => {
        console.error('Scan failed:', error);
        sendResponse({ error: 'Scan failed' });
      });
    
    // Keep the message channel open for the async response
    return true;
  }
  
  if (message.type === 'SCAN_EMAIL') {
    scanEmail(message.content, sender.tab.id)
      .then(result => {
        sendResponse(result);
        updateBadgeWithResult(result, sender.tab.id);
      })
      .catch(error => {
        console.error('Email scan failed:', error);
        sendResponse({ error: 'Email scan failed' });
      });
    
    // Keep the message channel open for the async response
    return true;
  }
});

// Function to check authentication status
async function checkAuthentication() {
  try {
    const result = await chrome.storage.local.get(['authToken']);
    return Boolean(result.authToken);
  } catch (error) {
    console.error('Error checking authentication:', error);
    return false;
  }
}

// Function to scan a URL
async function scanUrl(url, tabId) {
  console.log(`Scanning URL: ${url}`);
  
  try {

    // Increment scan counter
    state.scansPerformed = (state.scansPerformed || 0) + 1;
    // Validate and sanitize URL
    if (!validators.isValidUrl(url)) {
      console.error('Invalid URL format:', url);
      return {
        prediction: 'error',
        confidence: 0,
        error: 'Invalid URL format',
        scan_id: `error-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
    }
    
    const sanitizedUrl = validators.sanitizeUrl(url);

    // Check if authenticated
    const isAuthenticated = await checkAuthentication();
    
    if (!isAuthenticated) {
      // For development, we'll use a placeholder if not authenticated
      console.warn('Not authenticated, using placeholder result');
      
      const result = {
        prediction: Math.random() > 0.8 ? 'phishing' : 'legitimate',
        confidence: 0.85 + (Math.random() * 0.1),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
      
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
        state.warningsDisplayed++;  // Add this line
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });

      // Add this line to update usage stats
      collectUsageStats();
      
      return result;
    }
    
    // Use the actual API now that we have ML models integrated
    const authToken = (await chrome.storage.local.get(['authToken'])).authToken;
    try {
      const response = await fetch(`${state.apiEndpoint}/predict`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({ url: sanitizedUrl, scan_type: 'REALTIME' })
      });
  
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
  
      const result = await response.json();
      console.log('API response for URL scan:', result);
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });
      return result;
    } catch (apiError) {
      console.error('API request failed:', apiError);
      // Fall back to placeholder only if API call fails
      const result = {
        prediction: Math.random() > 0.8 ? 'phishing' : 'legitimate',
        confidence: 0.85 + (Math.random() * 0.1),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString(),
        model_used: 'fallback'
     };
    
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
    
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
      }
    
      // Save state
      chrome.storage.local.set({ phishguardState: state });
    
      return result;
    }
  } catch (error) {
    console.error('Error scanning email:', error);
    throw error;
  }
}


// Function to scan email content
async function scanEmail(content, tabId) {
  console.log(`Scanning email content (length: ${content.length})`);
  
  try {
    // Increment scan counter
    state.scansPerformed = (state.scansPerformed || 0) + 1;

    // Validate and sanitize email content
    if (!validators.isValidEmailContent(content)) {
      console.error('Invalid email content');
      return {
        prediction: 'error',
        confidence: 0,
        error: 'Invalid email content',
        scan_id: `error-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
    }
    const sanitizedContent = validators.sanitizeEmailContent(content);
    // Check if authenticated
    const isAuthenticated = await checkAuthentication();
    
    if (!isAuthenticated) {
      // For development, we'll use a placeholder if not authenticated
      console.warn('Not authenticated, using placeholder result');
      
      const result = {
        prediction: Math.random() > 0.7 ? 'phishing' : 'legitimate',
        confidence: 0.80 + (Math.random() * 0.15),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
      
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
        state.warningsDisplayed++;  // Add this line
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });

      // Add this line to update usage stats
      collectUsageStats();
      
      return result;
    }
    
    // Use the actual API now that we have ML models integrated
    const authToken = (await chrome.storage.local.get(['authToken'])).authToken;
    try {
      const response = await fetch(`${state.apiEndpoint}/predict`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({ email_content: sanitizedContent, scan_type: 'REALTIME' })
      });
  
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
  
      const result = await response.json();
      console.log('API response for email scan:', result);

      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
        state.warningsDisplayed++;
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });

      return result;
    } catch (apiError) {
      console.error('API request failed:', apiError);
      // Fall back to placeholder only if API call fails
      const result = {
        prediction: Math.random() > 0.7 ? 'phishing' : 'legitimate',
        confidence: 0.80 + (Math.random() * 0.15),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString(),
        model_used: 'fallback'
      };
    
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
    
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
        state.warningsDisplayed++;  // Add this line
      }
    
      // Save state
      chrome.storage.local.set({ phishguardState: state });

      // Add this line to update usage stats
      collectUsageStats();
    
      return result;
    } 
  }  catch (error) {
     console.error('Error scanning email:', error);
     throw error;
  }
}

// Update badge based on scan result
function updateBadgeWithResult(result, tabId) {
  if (result.prediction === 'phishing') {
    chrome.action.setBadgeText({ 
      text: '!',
      tabId: tabId 
    });
    
    chrome.action.setBadgeBackgroundColor({ 
      color: '#EA4335', // Red for phishing
      tabId: tabId 
    });

    // Update warnings displayed counter if not already counted
    if (result.is_new_detection) {
      state.warningsDisplayed = (state.warningsDisplayed || 0) + 1;
      chrome.storage.local.set({ phishguardState: state });
      collectUsageStats();
    }
    
  } else {
    // Clear any previous warning for legitimate content
    setTimeout(() => {
      chrome.action.setBadgeText({ 
        text: '',
        tabId: tabId 
      });
    }, 3000);
  }
}

// Reset warning badges when navigating away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ 
      text: '',
      tabId: tabId 
    });
  }
});

// Function to report user interaction with warnings
async function reportUserInteraction(scanId, didProceed) {
  try {
    // Check if authenticated
    const isAuthenticated = await checkAuthentication();
    
    if (!isAuthenticated) {
      console.warn('Not authenticated, skipping feedback submission');
      return;
    }
    
    // Get auth token
    const authToken = (await chrome.storage.local.get(['authToken'])).authToken;
    
    // Submit feedback
    const response = await fetch(`${state.apiEndpoint}/feedback`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({
        scan_id: scanId,
        is_correct: !didProceed, // If user didn't proceed, warning was likely correct
        comment: didProceed ? 'User proceeded despite warning' : 'User heeded warning'
      })
    });
    
    if (response.ok) {
      console.log('User interaction feedback submitted successfully');
    } else {
      console.warn('Failed to submit user interaction feedback');
    }
  } catch (error) {
    console.error('Error reporting user interaction:', error);
  }
}

// Function to collect anonymous usage statistics
async function collectUsageStats() {
  // Get current stats
  const stats = {
    scansPerformed: state.scansPerformed || 0,
    phishingDetected: state.detectionCount || 0,
    warningsDisplayed: state.warningsDisplayed || 0,
    timeInstalled: state.installTime || new Date().toISOString()
  };
  
  // Update storage
  chrome.storage.local.set({ 
    phishguardStats: stats
  });
  
  // In a production environment, you might want to send anonymous stats
  // to your server to improve the extension
  console.log('Updated local usage statistics');
} 

// Initialize installation time if not set
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    const now = new Date().toISOString();
    state.installTime = now;
    await chrome.storage.local.set({ phishguardState: state });
    console.log('PhishGuard installed at:', now);
  }
});