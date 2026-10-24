document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('fileInput');
  const dropArea = document.getElementById('dropArea');
  const fileName = document.getElementById('selectedFileName');
  const fileSize = document.getElementById('selectedFileSize');
  const message = document.getElementById('uploadMessage');
  const uploadButton = document.getElementById('uploadSubmit');
  const allowedTypes = new Set(['pdf', 'docx', 'xlsx', 'png', 'jpg', 'jpeg']);
  const maximumSize = 10 * 1024 * 1024;
  let selectedFile = null;

  fileInput.addEventListener('change', () => selectFile(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach((eventName) => {
    dropArea.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropArea.classList.add('drag-active');
    });
  });
  ['dragleave', 'drop'].forEach((eventName) => {
    dropArea.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropArea.classList.remove('drag-active');
    });
  });
  dropArea.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInput.files = transfer.files;
    selectFile(file);
  });
  dropArea.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInput.click();
    }
  });

  uploadButton.addEventListener('click', async () => {
    const validation = validate(selectedFile);
    if (validation) {
      showMessage(validation, 'error');
      return;
    }

    uploadButton.disabled = true;
    uploadButton.textContent = 'Uploading…';
    try {
      const result = await window.TrustVaultAPI.upload(selectedFile);
      showMessage(`${result.document.name} uploaded successfully.`, 'success');
      window.showToast('Document uploaded.', 'success');
      window.setTimeout(() => {
        window.location.href = 'documents.html';
      }, 800);
    } catch (error) {
      showMessage(error.message, 'error');
      window.showToast(error.message, 'error');
    } finally {
      uploadButton.disabled = false;
      uploadButton.textContent = 'Upload';
    }
  });

  function selectFile(file) {
    selectedFile = file || null;
    fileName.textContent = selectedFile ? selectedFile.name : 'No file chosen';
    fileSize.textContent = selectedFile ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB` : '-';
    if (!selectedFile) return;
    const validation = validate(selectedFile);
    showMessage(validation || 'File selected. Upload to send it to the server.', validation ? 'error' : 'info');
  }

  function validate(file) {
    if (!file) return 'Please select a file before uploading.';
    const extension = file.name.split('.').pop().toLowerCase();
    if (!allowedTypes.has(extension)) {
      return 'Unsupported file type. Choose a PDF, DOCX, XLSX, PNG, or JPG file.';
    }
    if (file.size > maximumSize) return 'The selected file exceeds the 10 MB limit.';
    return '';
  }

  function showMessage(text, type) {
    message.className = `form-status ${type}`;
    message.textContent = text;
  }
});
