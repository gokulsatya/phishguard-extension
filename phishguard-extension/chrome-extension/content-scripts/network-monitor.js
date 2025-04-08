/**
 * Network Monitor Content Script
 * Monitors outgoing requests for potential phishing indicators
 */

// Configuration for request monitoring
const config = {
    enabled: true,
    monitorForms: true,
    monitorRedirects: true,
    highRiskDomains: [
      'login', 'signin', 'account', 'secure', 'banking',
      'verify', 'password', 'credential', 'authenticate'
    ]
  };
  
  // Initialize monitor
  function initNetworkMonitor() {
    console.log('PhishGuard network monitor initialized');
    
    // Load configuration
    chrome.storage.local.get(['phishguardConfig'], (result) => {
      if (result.phishguardConfig && result.phishguardConfig.networkMonitor) {
        Object.assign(config, result.phishguardConfig.networkMonitor);
      }
    });
    
    // Setup form submission monitoring
    if (config.monitorForms) {
      monitorFormSubmissions();
    }
    
    // Setup link click monitoring for redirects
    if (config.monitorRedirects) {
      monitorLinkClicks();
    }
  }
  
  /**
   * Monitor form submissions to detect potential credential theft
   */
  function monitorFormSubmissions() {
    // Get all forms on the page
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      // Check if the form might be collecting sensitive information
      const hasSensitiveFields = containsSensitiveFields(form);
      
      if (hasSensitiveFields) {
        // Add a submission listener
        form.addEventListener('submit', async (event) => {
          // Check if the form is submitting to a suspicious domain
          const actionUrl = form.action || window.location.href;
          const isSuspicious = await isSuspiciousUrl(actionUrl);
          
          if (isSuspicious) {
            // Prevent the form submission
            event.preventDefault();
            
            // Show a warning to the user
            const proceed = confirm(`
              PhishGuard Warning: This form may be sending your information to a suspicious website.
              
              Form destination: ${actionUrl}
              
              Do you want to proceed anyway?
            `);
            
            if (proceed) {
              // User wants to proceed, submit the form programmatically
              form.submit();
            }
          }
        });
      }
    });
  }
  
  /**
   * Check if a form contains fields that could collect sensitive information
   */
  function containsSensitiveFields(form) {
    const sensitiveInputTypes = ['password', 'email', 'tel', 'number'];
    const sensitiveNamePatterns = [
      /pass(word)?/i, /email/i, /login/i, /user(name)?/i,
      /account/i, /card/i, /credit/i, /ssn/i, /social/i,
      /secur(e|ity)/i, /bank/i, /routing/i, /pin/i
    ];
    
    const inputs = form.querySelectorAll('input');
    
    for (const input of inputs) {
      // Check input type
      if (sensitiveInputTypes.includes(input.type)) {
        return true;
      }
      
      // Check input name, id, and placeholder attributes
      const attributes = [input.name, input.id, input.placeholder];
      
      for (const attr of attributes) {
        if (!attr) continue;
        
        for (const pattern of sensitiveNamePatterns) {
          if (pattern.test(attr)) {
            return true;
          }
        }
      }
    }
    
    return false;
  }
  
  /**
   * Monitor link clicks to check for suspicious redirects
   */
  function monitorLinkClicks() {
    // Add a global click event listener
    document.addEventListener('click', async (event) => {
      // Check if the clicked element is a link or within a link
      const link = event.target.closest('a');
      
      if (link && link.href) {
        // Only check http/https links
        if (link.href.startsWith('http')) {
          const isSuspicious = await isSuspiciousUrl(link.href);
          
          if (isSuspicious) {
            // Prevent the default navigation
            event.preventDefault();
            
            // Show a warning to the user
            const proceed = confirm(`
              PhishGuard Warning: You're about to visit a potentially suspicious website.
              
              URL: ${link.href}
              
              Do you want to proceed anyway?
            `);
            
            if (proceed) {
              // User wants to proceed, open the link
              window.open(link.href, link.target || '_self');
            }
          }
        }
      }
    });
  }
  
  /**
   * Check if a URL might be suspicious or a phishing attempt
   */
  async function isSuspiciousUrl(url) {
    try {
      // Parse the URL
      const urlObj = new URL(url);
      
      // Quick check: Does the domain contain suspicious keywords?
      for (const keyword of config.highRiskDomains) {
        if (urlObj.hostname.includes(keyword)) {
          // Potentially suspicious based on hostname, let's check with the background service
          return checkWithBackgroundService(url);
        }
      }
      
      // Quick check: Does the URL have an unusual number of subdomains?
      const subdomainCount = urlObj.hostname.split('.').length - 1;
      if (subdomainCount > 3) {
        // Suspicious number of subdomains
        return checkWithBackgroundService(url);
      }
      
      // Check for obfuscation techniques
      if (
        urlObj.hostname.includes('xn--') || // Punycode
        urlObj.hostname.length > 30 ||      // Very long hostname
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname) // IP address
      ) {
        return checkWithBackgroundService(url);
      }
      
      // Not suspicious based on quick checks
      return false;
    } catch (error) {
      console.error('Error checking URL:', error);
      return false;
    }
  }
  
  /**
   * Send the URL to the background service for a more thorough check
   */
  async function checkWithBackgroundService(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'SCAN_URL', url },
        (response) => {
          if (response && response.prediction === 'phishing') {
            resolve(true); // Suspicious
          } else {
            resolve(false); // Not suspicious
          }
        }
      );
      
      // Set a timeout in case the background service doesn't respond
      setTimeout(() => resolve(false), 1000);
    });
  }
  
  // Initialize the network monitor
  initNetworkMonitor();