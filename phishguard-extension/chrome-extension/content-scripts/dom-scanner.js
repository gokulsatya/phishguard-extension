// DOM Scanner for email content analysis

// Check if we're in an email client
const isGmail = window.location.hostname.includes('gmail.com');
const isOutlook = window.location.hostname.includes('outlook.com');
const isYahooMail = window.location.hostname.includes('yahoo.com') && window.location.pathname.includes('/mail');

// Main initialization function
function initScanner() {
  console.log('PhishGuard scanner initialized on:', window.location.hostname);
  
  // Set up DOM observers based on the email client
  if (isGmail) {
    setupGmailObserver();
  } else if (isOutlook) {
    setupOutlookObserver();
  } else if (isYahooMail) {
    setupYahooMailObserver();
  }
  
  // Also check for visible links on the page
  scanVisibleLinks();
}

// Set up observer for Gmail
function setupGmailObserver() {
  // Gmail selectors for email content
  const emailSelector = '.a3s.aiL';
  
  // Create mutation observer to detect when emails are opened
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length) {
        const emailContent = document.querySelector(emailSelector);
        if (emailContent) {
          scanEmailContent(emailContent.innerText);
        }
      }
    }
  });
  
  // Start observing changes to the DOM
  observer.observe(document.body, { childList: true, subtree: true });
}

// Set up observer for Outlook
function setupOutlookObserver() {
  // Outlook selectors for email content
  const emailSelector = '.readMessageContent';
  
  // Create mutation observer
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length) {
        const emailContent = document.querySelector(emailSelector);
        if (emailContent) {
          scanEmailContent(emailContent.innerText);
        }
      }
    }
  });
  
  // Start observing changes to the DOM
  observer.observe(document.body, { childList: true, subtree: true });
}

// Set up observer for Yahoo Mail
function setupYahooMailObserver() {
  // Yahoo Mail selectors for email content
  const emailSelector = '.message-content';
  
  // Create mutation observer
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length) {
        const emailContent = document.querySelector(emailSelector);
        if (emailContent) {
          scanEmailContent(emailContent.innerText);
        }
      }
    }
  });
  
  // Start observing changes to the DOM
  observer.observe(document.body, { childList: true, subtree: true });
}

// Function to scan email content
function scanEmailContent(content) {
  if (!content || content.length < 10) {
    return; // Skip very short content
  }
  
  console.log('Scanning email content:', content.substring(0, 100) + '...');
  
  // Send content to background script for analysis
  chrome.runtime.sendMessage(
    { type: 'SCAN_EMAIL', content },
    (response) => {
      if (response && response.prediction === 'phishing') {
        // Alert user about potential phishing
        showPhishingWarning(response);
      }
    }
  );
}

// Function to scan visible links on the page
function scanVisibleLinks() {
  const links = document.querySelectorAll('a[href^="http"]');
  
  for (const link of links) {
    // Don't scan common legitimate links to reduce API load
    if (isLikelyLegitimate(link.href)) {
      continue;
    }
    
    // Send URL to background script for analysis
    chrome.runtime.sendMessage(
      { type: 'SCAN_URL', url: link.href },
      (response) => {
        if (response && response.prediction === 'phishing') {
          // Mark this link as potentially dangerous
          markDangerousLink(link, response);
        }
      }
    );
  }
}

// Function to check if a URL is likely legitimate
function isLikelyLegitimate(url) {
  const safeHosts = [
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
    'yahoo.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'apple.com', 'github.com', 'wikipedia.org'
  ];
  
  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname;
    
    // Check if domain matches or ends with one of the safe hosts
    return safeHosts.some(safeHost => 
      host === safeHost || host.endsWith('.' + safeHost)
    );
  } catch (e) {
    return false;
  }
}

// Function to show a warning for phishing emails
function showPhishingWarning(result) {
  // Create warning element
  const warning = document.createElement('div');
  warning.style.backgroundColor = '#FEF0F0';
  warning.style.border = '1px solid #EA4335';
  warning.style.borderRadius = '8px';
  warning.style.padding = '10px 15px';
  warning.style.margin = '10px 0';
  warning.style.color = '#EA4335';
  warning.style.fontWeight = 'bold';
  warning.style.zIndex = '9999';
  
  warning.innerText = `⚠️ PHISHING WARNING: This email may be a phishing attempt (${Math.round(result.confidence * 100)}% confidence)`;
  
  // Find the appropriate location to insert the warning
  let container;
  
  if (isGmail) {
    container = document.querySelector('.a3s.aiL');
  } else if (isOutlook) {
    container = document.querySelector('.readMessageContent');
  } else if (isYahooMail) {
    container = document.querySelector('.message-content');
  }
  
  // Insert warning at the top of the email
  if (container && !container.querySelector('.phishguard-warning')) {
    warning.classList.add('phishguard-warning');
    container.insertBefore(warning, container.firstChild);
  }
}

// Function to mark dangerous links
function markDangerousLink(link, result) {
  // Style the dangerous link
  link.style.color = '#EA4335';
  link.style.borderBottom = '2px dashed #EA4335';
  link.style.fontWeight = 'bold';
  link.dataset.phishguardScanned = 'true';
  link.dataset.phishguardConfidence = Math.round(result.confidence * 100) + '%';
  
  // Add warning on hover
  link.title = `Warning: This link may be a phishing attempt (${Math.round(result.confidence * 100)}% confidence)`;
  
  // Prevent immediate click and show warning first
  const originalHref = link.href;
  link.addEventListener('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    
    if (confirm(`PHISHING WARNING: This link is suspicious and may be a phishing attempt.\n\nConfidence: ${Math.round(result.confidence * 100)}%\nURL: ${originalHref}\n\nDo you still want to proceed?`)) {
      window.open(originalHref, '_blank');
    }
  });
}

// Handle messages from popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getPageContent') {
    let content = '';
    if (isGmail) {
      // Try multiple selectors for Gmail
      content = document.querySelector('.a3s.aiL')?.innerText || 
                document.querySelector('.ii.gt')?.innerText || 
                document.querySelector('.message')?.innerText || '';
    } else if (isOutlook) {
      content = document.querySelector('.readMessageContent')?.innerText || '';
    } else if (isYahooMail) {
      content = document.querySelector('.message-content')?.innerText || '';
    } else {
      content = document.body.innerText || '';
    }
    console.log('Sending content to popup:', content.substring(0, 100));
    sendResponse({ content });
  }
  return true; // Keep channel open for async response
});

// Start the scanner
initScanner();