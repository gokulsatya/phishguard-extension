// Save to: chrome-extension/shared/validators.js

/**
 * Input validation utilities for the PhishGuard extension
 */

const validators = {
    /**
     * Validate a URL string
     * @param {string} url - The URL to validate
     * @returns {boolean} True if valid, false otherwise
     */
    isValidUrl: function(url) {
      if (!url || typeof url !== 'string') {
        return false;
      }
      
      // URL pattern matching
      const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
      return urlPattern.test(url);
    },
    
    /**
     * Validate email content
     * @param {string} content - The email content to validate
     * @returns {boolean} True if valid, false otherwise
     */
    isValidEmailContent: function(content) {
      if (!content || typeof content !== 'string') {
        return false;
      }
      
      // Basic validation - content should not be empty
      return content.trim().length > 0;
    },
    
    /**
     * Sanitize a URL string
     * @param {string} url - The URL to sanitize
     * @returns {string} The sanitized URL
     */
    sanitizeUrl: function(url) {
      if (!url || typeof url !== 'string') {
        return '';
      }
      
      // Basic sanitization
      // Remove whitespace and script tags
      let sanitized = url.trim();
      sanitized = sanitized.replace(/<script.*?>.*?<\/script>/gi, '');
      
      return sanitized;
    },
    
    /**
     * Sanitize email content
     * @param {string} content - The email content to sanitize
     * @returns {string} The sanitized content
     */
    sanitizeEmailContent: function(content) {
      if (!content || typeof content !== 'string') {
        return '';
      }
      
      // Basic sanitization
      // Remove script tags
      let sanitized = content.trim();
      sanitized = sanitized.replace(/<script.*?>.*?<\/script>/gi, '');
      
      return sanitized;
    }
  };
  
  // Make available to other extension scripts
  if (typeof window !== 'undefined') {
    window.validators = validators;
  }