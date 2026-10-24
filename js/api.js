window.TrustVaultAPI = {
  async request(endpoint, options = {}) {
    const headers = new Headers(options.headers || {});
    const method = (options.method || 'GET').toUpperCase();
    const csrfToken = readCookie('tv_csrf');

    if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      headers.set('X-CSRF-Token', csrfToken);
    }
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
      options.body = JSON.stringify(options.body);
    }

    let response;
    try {
      response = await fetch(endpoint, {
        ...options,
        method,
        headers,
        credentials: 'same-origin'
      });
    } catch (_error) {
      throw new Error('Could not reach the TrustVault server. Check that Flask is running.');
    }

    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json() : {};
    if (!response.ok) {
      const error = new Error(data.error || 'The request could not be completed.');
      error.status = response.status;
      throw error;
    }
    return data;
  },

  auth: {
    register(payload) {
      return window.TrustVaultAPI.request('/api/auth/register', { method: 'POST', body: payload });
    },
    login(payload) {
      return window.TrustVaultAPI.request('/api/auth/login', { method: 'POST', body: payload });
    },
    currentUser() {
      return window.TrustVaultAPI.request('/api/auth/me');
    },
    logout() {
      return window.TrustVaultAPI.request('/api/auth/logout', { method: 'POST' });
    }
  },

  dashboard() {
    return window.TrustVaultAPI.request('/api/dashboard');
  },
  documents() {
    return window.TrustVaultAPI.request('/api/documents');
  },
  upload(file) {
    const body = new FormData();
    body.append('file', file);
    return window.TrustVaultAPI.request('/api/documents/upload', { method: 'POST', body });
  },
  viewDocument(id) {
    return window.TrustVaultAPI.request(`/api/documents/${encodeURIComponent(id)}/view`, { method: 'POST' });
  },
  async downloadDocument(id) {
    let response;
    try {
      response = await fetch(`/api/documents/${encodeURIComponent(id)}/download`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': readCookie('tv_csrf') }
      });
    } catch (_error) {
      throw new Error('Could not reach the TrustVault server. Check that Flask is running.');
    }
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || 'The document could not be downloaded.');
    }
    const blobUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    const disposition = response.headers.get('Content-Disposition') || '';
    const filename = disposition.match(/filename="?([^";]+)"?/i);
    link.href = blobUrl;
    link.download = filename ? filename[1] : 'TrustVault-document';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  },
  shared() {
    return window.TrustVaultAPI.request('/api/shared');
  },
  permissions() {
    return window.TrustVaultAPI.request('/api/permissions');
  },
  share(payload) {
    return window.TrustVaultAPI.request('/api/permissions', { method: 'POST', body: payload });
  },
  revokePermission(id) {
    return window.TrustVaultAPI.request(`/api/permissions/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  audit({ search = '', action = '' } = {}) {
    const query = new URLSearchParams();
    if (search) query.set('search', search);
    if (action && action !== 'all') query.set('action', action);
    return window.TrustVaultAPI.request(`/api/audit?${query.toString()}`);
  }
};

function readCookie(name) {
  const prefix = `${name}=`;
  const cookie = document.cookie.split('; ').find((item) => item.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : '';
}
