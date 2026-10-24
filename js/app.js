document.addEventListener('DOMContentLoaded', () => {
  window.showToast = (message, type = 'info') => {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    window.setTimeout(() => toast.remove(), 4000);
  };

  document.querySelectorAll('[data-toggle-password]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      button.textContent = reveal ? 'Hide' : 'Show';
      button.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
    });
  });

  const sidebar = document.querySelector('.sidebar');
  const mobileToggle = document.querySelector('.mobile-nav-toggle');
  if (sidebar && mobileToggle) {
    const updateSidebar = () => {
      if (window.innerWidth > 980) {
        sidebar.style.display = '';
        sidebar.classList.remove('is-open');
      } else {
        sidebar.style.display = sidebar.classList.contains('is-open') ? 'flex' : '';
      }
    };
    mobileToggle.addEventListener('click', () => {
      sidebar.classList.toggle('is-open');
      updateSidebar();
    });
    window.addEventListener('resize', updateSidebar);
    updateSidebar();
  }

  document.querySelectorAll('.logout-link').forEach((link) => {
    link.addEventListener('click', async (event) => {
      event.preventDefault();
      try {
        await window.TrustVaultAPI.auth.logout();
        window.location.href = 'index.html';
      } catch (error) {
        window.showToast(error.message, 'error');
      }
    });
  });

  const page = document.body.dataset.page;
  if (page && window.TrustVaultAPI) {
    initializeProtectedPage(page);
  }

  if (page === 'dashboard') {
    loadDashboard();
  }

  async function initializeProtectedPage(currentPage) {
    try {
      const { user } = await window.TrustVaultAPI.auth.currentUser();
      const name = user.full_name || 'TrustVault user';
      const initials = name.split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase();
      document.querySelectorAll('.user-pill strong').forEach((element) => {
        element.textContent = name;
      });
      document.querySelectorAll('.user-avatar').forEach((element) => {
        element.textContent = initials;
      });
      const heading = document.querySelector('.topbar h2');
      if (currentPage === 'dashboard' && heading) {
        heading.textContent = `Welcome back, ${name.split(/\s+/)[0]}`;
      }
    } catch (error) {
      if (error.status === 401) {
        const next = encodeURIComponent(window.location.pathname.split('/').pop());
        window.location.replace(`index.html?next=${next}`);
        return;
      }
      window.showToast(error.message, 'error');
    }
  }

  async function loadDashboard() {
    try {
      const data = await window.TrustVaultAPI.dashboard();
      setText('[data-stat="documents"]', data.total_documents);
      setText('[data-stat="shared"]', data.shared_documents);
      setText('[data-stat="audit"]', data.audit_events);
      renderActivity(data.recent_activity || []);
    } catch (error) {
      setText('[data-stat="documents"]', 'Unavailable');
      setText('[data-stat="shared"]', 'Unavailable');
      setText('[data-stat="audit"]', 'Unavailable');
      renderActivity([]);
      const activity = document.querySelector('.activity-empty');
      if (activity) activity.textContent = error.message;
      window.showToast(error.message, 'error');
    }
  }

  function setText(selector, value) {
    const element = document.querySelector(selector);
    if (element) element.textContent = String(value);
  }

  function renderActivity(records) {
    const list = document.querySelector('.activity-list');
    if (!list) return;
    list.replaceChildren();
    if (!records.length) {
      const item = document.createElement('li');
      item.className = 'activity-empty';
      item.textContent = 'No recent activity yet.';
      list.appendChild(item);
      return;
    }

    records.forEach((record) => {
      const item = document.createElement('li');
      const dot = document.createElement('span');
      dot.className = `activity-dot ${record.action === 'Upload' ? 'success' : record.action === 'Share' ? 'info' : 'warning'}`;
      const details = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = record.document;
      const description = document.createElement('p');
      description.textContent = `${record.action} by ${record.actor}`;
      const time = document.createElement('time');
      time.dateTime = record.created_at;
      time.textContent = new Date(record.created_at).toLocaleString();
      details.append(title, description);
      item.append(dot, details, time);
      list.appendChild(item);
    });
  }
});
