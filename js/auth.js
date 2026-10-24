document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');

  if (new URLSearchParams(window.location.search).get('registered') === '1') {
    window.showToast('Account created. Log in with your new credentials.', 'success');
  }

  if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearErrors(loginForm);
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value;
      let invalid = false;

      if (!email) {
        showError('loginEmail', 'Email is required.');
        invalid = true;
      } else if (!isValidEmail(email)) {
        showError('loginEmail', 'Enter a valid email address.');
        invalid = true;
      }
      if (!password) {
        showError('loginPassword', 'Password is required.');
        invalid = true;
      }
      if (invalid) return;

      setFormBusy(loginForm, true);
      try {
        await window.TrustVaultAPI.auth.login({ email, password });
        const next = new URLSearchParams(window.location.search).get('next');
        const allowedNext = ['dashboard.html', 'documents.html', 'upload.html', 'shared.html', 'permissions.html', 'audit.html'];
        window.location.href = allowedNext.includes(next) ? next : 'dashboard.html';
      } catch (error) {
        showError('loginPassword', error.message);
      } finally {
        setFormBusy(loginForm, false);
      }
    });
  }

  if (registerForm) {
    const passwordInput = document.getElementById('registerPassword');
    passwordInput.addEventListener('input', () => updatePasswordStrength(passwordInput.value));
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearErrors(registerForm);

      const name = document.getElementById('fullName').value.trim();
      const email = document.getElementById('registerEmail').value.trim();
      const password = passwordInput.value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      let invalid = false;

      if (!name) {
        showError('fullName', 'Full name is required.');
        invalid = true;
      }
      if (!email) {
        showError('registerEmail', 'Email is required.');
        invalid = true;
      } else if (!isValidEmail(email)) {
        showError('registerEmail', 'Enter a valid email address.');
        invalid = true;
      }
      if (!password) {
        showError('registerPassword', 'Password is required.');
        invalid = true;
      } else if (password.length < 8) {
        showError('registerPassword', 'Password must be at least 8 characters long.');
        invalid = true;
      }
      if (!confirmPassword) {
        showError('confirmPassword', 'Please confirm your password.');
        invalid = true;
      } else if (password !== confirmPassword) {
        showError('confirmPassword', 'Passwords do not match.');
        invalid = true;
      }
      if (invalid) return;

      setFormBusy(registerForm, true);
      try {
        await window.TrustVaultAPI.auth.register({ full_name: name, email, password });
        window.location.href = 'index.html?registered=1';
      } catch (error) {
        if (error.status === 409) {
          showError('registerEmail', error.message);
        } else {
          window.showToast(error.message, 'error');
        }
      } finally {
        setFormBusy(registerForm, false);
      }
    });
  }

  function setFormBusy(form, busy) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? 'Please wait…' : button.dataset.defaultLabel;
  }

  function clearErrors(form) {
    form.querySelectorAll('.error-message').forEach((node) => {
      node.textContent = '';
    });
  }

  function showError(fieldId, message) {
    const errorNode = document.querySelector(`[data-error-for="${fieldId}"]`);
    if (errorNode) errorNode.textContent = message;
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function updatePasswordStrength(password) {
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');
    const score = calculatePasswordStrength(password);
    strengthBar.style.width = `${score.percent}%`;
    strengthBar.style.background = score.color;
    strengthText.textContent = score.label;
    strengthText.style.color = score.color;
  }

  function calculatePasswordStrength(value) {
    if (!value) return { percent: 0, color: '#B84242', label: 'Use at least 8 characters.' };
    let score = 0;
    if (value.length >= 8) score += 30;
    if (/[A-Z]/.test(value)) score += 20;
    if (/[0-9]/.test(value)) score += 20;
    if (/[^A-Za-z0-9]/.test(value)) score += 20;
    if (value.length >= 12) score += 10;
    if (score < 40) return { percent: 35, color: '#B84242', label: 'Weak password' };
    if (score < 70) return { percent: 65, color: '#d89a45', label: 'Moderate password' };
    return { percent: 100, color: '#168C78', label: 'Strong password' };
  }
});
