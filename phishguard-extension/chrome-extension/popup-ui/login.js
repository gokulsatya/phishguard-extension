// Save to: chrome-extension/popup-ui/login.js

document.addEventListener('DOMContentLoaded', function() {
    const loginButton = document.getElementById('login-button');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const loginError = document.getElementById('login-error');
    
    // Add event listener for login button
    loginButton.addEventListener('click', async function() {
      // Clear previous errors
      loginError.textContent = '';
      loginError.classList.add('hidden');
      
      // Get input values
      const email = emailInput.value.trim();
      const password = passwordInput.value;
      
      // Basic validation
      if (!email || !password) {
        loginError.textContent = 'Please enter both email and password';
        loginError.classList.remove('hidden');
        return;
      }
      
      // Show loading state
      loginButton.disabled = true;
      loginButton.textContent = 'Logging in...';
      
      try {
        // Attempt to log in
        const result = await window.phishGuardAPI.login(email, password);
        
        if (result.success) {
          // Redirect to main popup
          window.location.href = 'popup.html';
        } else {
          throw new Error('Login failed');
        }
      } catch (error) {
        loginError.textContent = error.message || 'Login failed. Please try again.';
        loginError.classList.remove('hidden');
        
        // Reset button
        loginButton.disabled = false;
        loginButton.textContent = 'Log In';
      }
    });
  });