document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  const state = { documents: [], shared: [], permissions: [], audit: [] };
  let auditRequestId = 0;
  let auditDebounce;

  if (page === 'documents') initializeDocuments();
  if (page === 'shared') initializeShared();
  if (page === 'permissions') initializePermissions();
  if (page === 'audit') initializeAudit();

  async function initializeDocuments() {
    bindDocumentFilters();
    try {
      const data = await window.TrustVaultAPI.documents();
      state.documents = data.documents;
      renderDocuments();
    } catch (error) {
      showLoadError('documentsEmpty', error.message);
    }
  }

  function bindDocumentFilters() {
    document.getElementById('documentSearch')?.addEventListener('input', renderDocuments);
    document.getElementById('documentFilter')?.addEventListener('change', renderDocuments);
    document.getElementById('documentsTable')?.addEventListener('click', handleDocumentAction);
  }

  function renderDocuments() {
    const search = document.getElementById('documentSearch').value.trim().toLowerCase();
    const type = document.getElementById('documentFilter').value;
    const results = state.documents.filter((document) => {
      return document.name.toLowerCase().includes(search) && (type === 'all' || document.type === type);
    });
    const body = document.getElementById('documentsTable');
    body.replaceChildren();
    results.forEach((doc) => {
      const row = document.createElement('tr');
      row.append(
        cell(doc.name),
        cell(doc.type),
        cell(formatDate(doc.uploaded)),
        badgeCell(doc.status, statusClass(doc.status))
      );
      const actions = document.createElement('td');
      actions.append(
        actionButton('View Details', 'view', doc.id, 'primary'),
        actionButton('Download', 'download', doc.id),
        actionButton('Share', 'share', doc.id)
      );
      row.appendChild(actions);
      body.appendChild(row);
    });
    setEmptyState('documentsEmpty', results.length === 0, state.documents.length ? 'No matching documents.' : 'No documents have been uploaded yet.');
  }

  async function handleDocumentAction(event) {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const documentId = button.dataset.id;
    if (button.dataset.action === 'download') {
      try {
        await window.TrustVaultAPI.downloadDocument(documentId);
      } catch (error) {
        window.showToast(error.message, 'error');
      }
    } else if (button.dataset.action === 'view') {
      try {
        const data = await window.TrustVaultAPI.viewDocument(documentId);
        window.showToast(`${data.document.name} · ${formatBytes(data.document.size)} · ${data.permission}`, 'success');
      } catch (error) {
        window.showToast(error.message, 'error');
      }
    } else if (button.dataset.action === 'share') {
      window.location.href = `permissions.html?document=${encodeURIComponent(documentId)}`;
    }
  }

  async function initializeShared() {
    document.getElementById('sharedSearch')?.addEventListener('input', renderShared);
    document.getElementById('sharedTable')?.addEventListener('click', handleSharedAction);
    try {
      const data = await window.TrustVaultAPI.shared();
      state.shared = data.documents;
      renderShared();
    } catch (error) {
      showLoadError('sharedEmpty', error.message);
    }
  }

  function renderShared() {
    const search = document.getElementById('sharedSearch').value.trim().toLowerCase();
    const results = state.shared.filter((item) => item.name.toLowerCase().includes(search));
    const body = document.getElementById('sharedTable');
    body.replaceChildren();
    results.forEach((item) => {
      const row = document.createElement('tr');
      row.append(cell(item.name), cell(item.sharedBy), cell(formatDate(item.date)), badgeCell(item.permission, 'shared'));
      const actions = document.createElement('td');
      actions.append(actionButton('View', 'view', item.id, 'primary'));
      if (item.permission === 'Download') actions.append(actionButton('Download', 'download', item.id));
      row.appendChild(actions);
      body.appendChild(row);
    });
    setEmptyState('sharedEmpty', results.length === 0, state.shared.length ? 'No matching shared documents.' : 'No documents have been shared with you yet.');
  }

  async function handleSharedAction(event) {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    if (button.dataset.action === 'download') {
      try {
        await window.TrustVaultAPI.downloadDocument(button.dataset.id);
      } catch (error) {
        window.showToast(error.message, 'error');
      }
      return;
    }
    try {
      const data = await window.TrustVaultAPI.viewDocument(button.dataset.id);
      window.showToast(`${data.document.name} · shared by ${data.owner} · ${data.permission} access`, 'success');
    } catch (error) {
      window.showToast(error.message, 'error');
    }
  }

  async function initializePermissions() {
    document.getElementById('sharePermissionForm')?.addEventListener('submit', submitShare);
    document.getElementById('permissionsTable')?.addEventListener('click', handlePermissionAction);
    try {
      const [documentData, permissionData] = await Promise.all([
        window.TrustVaultAPI.documents(),
        window.TrustVaultAPI.permissions()
      ]);
      state.documents = documentData.documents;
      state.permissions = permissionData.permissions;
      renderDocumentOptions();
      renderPermissions();
      const selectedDocument = new URLSearchParams(window.location.search).get('document');
      if (selectedDocument && state.documents.some((item) => String(item.id) === selectedDocument)) {
        document.getElementById('permissionDocument').value = selectedDocument;
      }
    } catch (error) {
      renderPermissionMessage(error.message);
      window.showToast(error.message, 'error');
    }
  }

  function renderDocumentOptions() {
    const select = document.getElementById('permissionDocument');
    const placeholder = select.options[0];
    select.replaceChildren(placeholder);
    state.documents.forEach((item) => {
      const option = document.createElement('option');
      option.value = item.id;
      option.textContent = item.name;
      select.appendChild(option);
    });
  }

  function renderPermissions() {
    const body = document.getElementById('permissionsTable');
    body.replaceChildren();
    state.permissions.forEach((item) => {
      const row = document.createElement('tr');
      row.append(
        cell(item.document),
        cell(item.recipient),
        badgeCell(item.permission, 'shared'),
        badgeCell(item.status, 'active')
      );
      const action = document.createElement('td');
      action.append(actionButton('Revoke Access', 'revoke', item.id, 'danger'));
      row.appendChild(action);
      body.appendChild(row);
    });
    if (!state.permissions.length) {
      renderPermissionMessage('No active sharing permissions.');
    }
  }

  function renderPermissionMessage(message) {
    const body = document.getElementById('permissionsTable');
    if (!body) return;
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.textContent = message;
    row.appendChild(cell);
    body.replaceChildren(row);
  }

  async function submitShare(event) {
    event.preventDefault();
    clearPermissionErrors();
    const documentId = document.getElementById('permissionDocument').value;
    const recipientEmail = document.getElementById('recipientEmail').value.trim();
    const permission = document.getElementById('permissionLevel').value;
    let invalid = false;
    if (!documentId) {
      showPermissionError('permissionDocument', 'Please choose a document.');
      invalid = true;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipientEmail)) {
      showPermissionError('recipientEmail', 'Enter a valid recipient email.');
      invalid = true;
    }
    if (!permission) {
      showPermissionError('permissionLevel', 'Choose a permission level.');
      invalid = true;
    }
    if (invalid) return;

    const button = event.currentTarget.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const result = await window.TrustVaultAPI.share({
        document_id: Number(documentId),
        recipient_email: recipientEmail,
        permission
      });
      window.showToast(result.message, 'success');
      document.getElementById('recipientEmail').value = '';
      const updated = await window.TrustVaultAPI.permissions();
      state.permissions = updated.permissions;
      renderPermissions();
    } catch (error) {
      window.showToast(error.message, 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function handlePermissionAction(event) {
    const button = event.target.closest('[data-action="revoke"]');
    if (!button) return;
    if (!window.confirm('Revoke this recipient’s access to the document?')) return;
    button.disabled = true;
    try {
      const result = await window.TrustVaultAPI.revokePermission(button.dataset.id);
      window.showToast(result.message, 'success');
      state.permissions = state.permissions.filter((item) => String(item.id) !== button.dataset.id);
      renderPermissions();
    } catch (error) {
      window.showToast(error.message, 'error');
      button.disabled = false;
    }
  }

  async function initializeAudit() {
    document.getElementById('auditSearch')?.addEventListener('input', loadAudit);
    document.getElementById('auditFilter')?.addEventListener('change', loadAudit);
    await loadAudit();
  }

  async function loadAudit() {
    const requestId = ++auditRequestId;
    window.clearTimeout(auditDebounce);
    await new Promise((resolve) => {
      auditDebounce = window.setTimeout(resolve, 150);
    });
    if (requestId !== auditRequestId) return;

    try {
      const data = await window.TrustVaultAPI.audit({
        search: document.getElementById('auditSearch').value.trim(),
        action: document.getElementById('auditFilter').value
      });
      if (requestId !== auditRequestId) return;
      state.audit = data.events;
      renderAudit();
    } catch (error) {
      if (requestId !== auditRequestId) return;
      showLoadError('auditEmpty', error.message);
    }
  }

  function renderAudit() {
    const body = document.getElementById('auditTable');
    body.replaceChildren();
    state.audit.forEach((item) => {
      const row = document.createElement('tr');
      row.append(
        badgeCell(item.action, statusClass(item.action)),
        cell(item.actor),
        cell(item.document),
        cell(formatDate(item.date))
      );
      body.appendChild(row);
    });
    setEmptyState('auditEmpty', state.audit.length === 0, 'No matching audit records.');
  }

  function actionButton(label, action, id, extraClass = '') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `action-button ${extraClass}`.trim();
    button.dataset.action = action;
    button.dataset.id = id;
    button.textContent = label;
    return button;
  }

  function cell(value) {
    const element = document.createElement('td');
    element.textContent = value == null ? '' : String(value);
    return element;
  }

  function badgeCell(value, className) {
    const element = cell('');
    const badge = document.createElement('span');
    badge.className = `status-badge ${className}`;
    badge.textContent = value;
    element.appendChild(badge);
    return element;
  }

  function setEmptyState(id, show, message) {
    const element = document.getElementById(id);
    element.classList.toggle('hidden', !show);
    const paragraph = element.querySelector('p');
    if (paragraph) paragraph.textContent = message;
    const table = element.previousElementSibling;
    if (table?.classList.contains('table-wrap')) table.classList.toggle('hidden', show);
  }

  function showLoadError(id, message) {
    setEmptyState(id, true, message);
  }

  function clearPermissionErrors() {
    document.querySelectorAll('.error-message').forEach((node) => {
      node.textContent = '';
    });
  }

  function showPermissionError(fieldId, message) {
    const node = document.querySelector(`[data-error-for="${fieldId}"]`);
    if (node) node.textContent = message;
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }

  function formatBytes(bytes) {
    return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  }

  function statusClass(status) {
    if (status === 'Active' || status === 'Shared' || status === 'Upload' || status === 'View') return 'active';
    if (status === 'Download' || status === 'Share') return 'success';
    if (status === 'Pending') return 'warning';
    return 'pending';
  }
});
