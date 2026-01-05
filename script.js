// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
    // Backend API URL - change this to your deployed backend
    API_BASE_URL: 'http://localhost:5000/api',
    
    // Frontend fallback (using localStorage if backend not available)
    FILE_STORAGE_KEY: 'ruach_church_files',
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    MAX_STORAGE: 50 * 1024 * 1024, // 50MB
    
    FILE_ICONS: {
        pdf: 'fas fa-file-pdf',
        doc: 'fas fa-file-word',
        docx: 'fas fa-file-word',
        txt: 'fas fa-file-alt',
        jpg: 'fas fa-file-image',
        jpeg: 'fas fa-file-image',
        png: 'fas fa-file-image',
        gif: 'fas fa-file-image',
        mp3: 'fas fa-file-audio',
        wav: 'fas fa-file-audio',
        mp4: 'fas fa-file-video',
        mov: 'fas fa-file-video',
        zip: 'fas fa-file-archive',
        rar: 'fas fa-file-archive',
        default: 'fas fa-file'
    },
    
    CATEGORY_LABELS: {
        sermon: 'Sermon Notes',
        event: 'Event Photos',
        form: 'Forms/Documents',
        music: 'Worship Music',
        other: 'Other'
    }
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

function getFileExtension(filename) {
    return filename.split('.').pop().toLowerCase();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString, full = false) {
    const date = new Date(dateString);
    
    if (full) {
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    const now = new Date();
    const diff = now - date;
    const diffDays = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function truncateFileName(name, maxLength) {
    if (name.length <= maxLength) return name;
    const extension = getFileExtension(name);
    const nameWithoutExt = name.substring(0, name.length - extension.length - 1);
    const truncated = nameWithoutExt.substring(0, maxLength - 3);
    return `${truncated}...${extension}`;
}

function showToast(message, type = 'info') {
    // Remove existing toasts
    document.querySelectorAll('.toast').forEach(toast => toast.remove());
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        background: ${type === 'success' ? '#2ecc71' : type === 'error' ? '#e74c3c' : '#3498db'};
        color: white;
        border-radius: 5px;
        z-index: 10000;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-weight: 500;
    `;
    
    document.body.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (toast.parentNode) {
                document.body.removeChild(toast);
            }
        }, 300);
    }, 3000);
}

// ============================================
// BACKEND API SERVICE
// ============================================

class ApiService {
    constructor() {
        this.baseUrl = CONFIG.API_BASE_URL;
        this.token = localStorage.getItem('church_admin_token');
        this.useBackend = false;
        this.checkBackend();
    }
    
    async checkBackend() {
        try {
            const response = await fetch(`${this.baseUrl}/health`, { timeout: 3000 });
            if (response.ok) {
                this.useBackend = true;
                console.log('✅ Backend connected');
            }
        } catch (error) {
            console.log('⚠️ Using frontend storage (backend not available)');
            this.useBackend = false;
        }
    }
    
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        return headers;
    }
    
    async login(username, password) {
        if (!this.useBackend) {
            // Fallback to frontend authentication
            return this.frontendLogin(username, password);
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/auth/login`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                this.token = data.token;
                localStorage.setItem('church_admin_token', this.token);
                localStorage.setItem('church_admin_user', JSON.stringify(data.user));
                return { success: true, user: data.user };
            } else {
                return { success: false, message: data.error || 'Login failed' };
            }
        } catch (error) {
            console.error('Backend login failed, falling back to frontend');
            return this.frontendLogin(username, password);
        }
    }
    
    frontendLogin(username, password) {
        // Simple frontend authentication (for demo)
        const adminUsers = [
            { username: 'admin', password: 'admin123', role: 'admin' },
            { username: 'pastor', password: 'pastor123', role: 'pastor' },
            { username: 'staff', password: 'staff123', role: 'staff' }
        ];
        
        const user = adminUsers.find(u => u.username === username && u.password === password);
        
        if (user) {
            this.token = 'frontend-token-' + Date.now();
            localStorage.setItem('church_admin_token', this.token);
            localStorage.setItem('church_admin_user', JSON.stringify(user));
            return { success: true, user };
        }
        
        return { success: false, message: 'Invalid credentials' };
    }
    
    async verifyToken() {
        if (!this.token) return { valid: false };
        
        if (!this.useBackend) {
            // Check frontend token
            const userStr = localStorage.getItem('church_admin_user');
            if (userStr) {
                try {
                    const user = JSON.parse(userStr);
                    return { valid: true, user };
                } catch (e) {
                    return { valid: false };
                }
            }
            return { valid: false };
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/auth/verify`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            if (response.ok) {
                const data = await response.json();
                return { valid: true, user: data.user };
            }
        } catch (error) {
            console.error('Token verification failed');
        }
        
        return { valid: false };
    }
    
    logout() {
        this.token = null;
        localStorage.removeItem('church_admin_token');
        localStorage.removeItem('church_admin_user');
        
        if (this.useBackend) {
            fetch(`${this.baseUrl}/auth/logout`, { 
                method: 'POST',
                headers: this.getHeaders() 
            }).catch(console.error);
        }
    }
    
    async uploadFiles(files, category, description, visibility = 'public') {
        if (!this.token) {
            throw new Error('Authentication required');
        }
        
        if (this.useBackend) {
            return this.backendUpload(files, category, description, visibility);
        } else {
            return this.frontendUpload(files, category, description);
        }
    }
    
    async backendUpload(files, category, description, visibility) {
        const formData = new FormData();
        
        files.forEach(file => {
            formData.append('files', file);
        });
        
        formData.append('category', category);
        formData.append('description', description);
        formData.append('visibility', visibility);
        
        try {
            const response = await fetch(`${this.baseUrl}/upload`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` },
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                return { success: true, data };
            } else {
                throw new Error(data.error || 'Upload failed');
            }
        } catch (error) {
            throw error;
        }
    }
    
    frontendUpload(files, category, description) {
        const uploadedFiles = [];
        
        for (const file of files) {
            const fileObject = {
                id: Date.now() + Math.random(),
                name: file.name,
                size: file.size,
                type: file.type,
                extension: getFileExtension(file.name),
                category: category,
                description: description,
                uploadedBy: 'Admin',
                uploadDate: new Date().toISOString(),
                downloads: 0,
                visibility: 'public'
            };
            
            this.saveFileToStorage(fileObject);
            uploadedFiles.push(fileObject);
        }
        
        return { success: true, files: uploadedFiles };
    }
    
    async getFiles(category = '', search = '', page = 1) {
        if (this.useBackend) {
            try {
                let url = `${this.baseUrl}/files?page=${page}`;
                if (category) url += `&category=${category}`;
                if (search) url += `&search=${encodeURIComponent(search)}`;
                
                const response = await fetch(url);
                const data = await response.json();
                
                if (response.ok) {
                    return { success: true, files: data.files, total: data.total };
                }
            } catch (error) {
                console.error('Backend files fetch failed, using frontend');
            }
        }
        
        // Frontend fallback
        const files = this.getStoredFiles();
        let filteredFiles = files;
        
        if (category) {
            filteredFiles = filteredFiles.filter(f => f.category === category);
        }
        
        if (search) {
            const searchLower = search.toLowerCase();
            filteredFiles = filteredFiles.filter(f => 
                f.name.toLowerCase().includes(searchLower) || 
                (f.description && f.description.toLowerCase().includes(searchLower))
            );
        }
        
        return { 
            success: true, 
            files: filteredFiles, 
            total: filteredFiles.length 
        };
    }
    
    async downloadFile(file) {
        if (file.url && this.useBackend) {
            // Backend download
            window.open(`${this.baseUrl}/files/download/${file.id}`, '_blank');
        } else {
            // Frontend download
            const link = document.createElement('a');
            link.href = file.data || '#';
            link.download = file.name;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Update download count
        this.incrementDownloadCount(file.id);
        return { success: true };
    }
    
    // Frontend storage methods
    getStoredFiles() {
        const filesJson = localStorage.getItem(CONFIG.FILE_STORAGE_KEY);
        return filesJson ? JSON.parse(filesJson) : [];
    }
    
    saveFileToStorage(fileObject) {
        const files = this.getStoredFiles();
        files.push(fileObject);
        localStorage.setItem(CONFIG.FILE_STORAGE_KEY, JSON.stringify(files));
    }
    
    incrementDownloadCount(fileId) {
        const files = this.getStoredFiles();
        const fileIndex = files.findIndex(f => f.id === fileId);
        if (fileIndex !== -1) {
            files[fileIndex].downloads = (files[fileIndex].downloads || 0) + 1;
            localStorage.setItem(CONFIG.FILE_STORAGE_KEY, JSON.stringify(files));
        }
    }
    
    deleteFile(fileId) {
        if (this.useBackend) {
            return fetch(`${this.baseUrl}/files/${fileId}`, {
                method: 'DELETE',
                headers: this.getHeaders()
            });
        } else {
            const files = this.getStoredFiles();
            const filteredFiles = files.filter(f => f.id !== fileId);
            localStorage.setItem(CONFIG.FILE_STORAGE_KEY, JSON.stringify(filteredFiles));
            return Promise.resolve({ ok: true });
        }
    }
}

// ============================================
// ADMIN AUTHENTICATION SYSTEM
// ============================================

class AdminAuth {
    constructor() {
        this.api = new ApiService();
        this.isAuthenticated = false;
        this.currentUser = null;
        this.init();
    }
    
    async init() {
        const result = await this.api.verifyToken();
        this.isAuthenticated = result.valid;
        this.currentUser = result.user;
        
        if (this.isAuthenticated) {
            this.showAdminInterface();
        }
        
        this.setupEventListeners();
    }
    
    async login(username, password) {
        const result = await this.api.login(username, password);
        
        if (result.success) {
            this.isAuthenticated = true;
            this.currentUser = result.user;
            this.showAdminInterface();
            showToast(`Welcome, ${result.user.username}!`, 'success');
            return true;
        } else {
            showToast(result.message || 'Login failed', 'error');
            return false;
        }
    }
    
    logout() {
        this.api.logout();
        this.isAuthenticated = false;
        this.currentUser = null;
        this.hideAdminInterface();
        showToast('Logged out successfully', 'success');
    }
    
    showAdminInterface() {
        const adminControls = document.getElementById('adminControls');
        const uploadSection = document.getElementById('uploadSection');
        const publicMessage = document.getElementById('publicMessage');
        const adminLoginLink = document.getElementById('adminLoginLink');
        
        if (adminControls) adminControls.style.display = 'block';
        if (uploadSection) uploadSection.style.display = 'block';
        if (publicMessage) publicMessage.style.display = 'none';
        if (adminLoginLink) {
            adminLoginLink.innerHTML = '<i class="fas fa-user-shield"></i> Logout';
            adminLoginLink.onclick = (e) => {
                e.preventDefault();
                this.logout();
                showPage('home');
            };
        }
    }
    
    hideAdminInterface() {
        const adminControls = document.getElementById('adminControls');
        const uploadSection = document.getElementById('uploadSection');
        const publicMessage = document.getElementById('publicMessage');
        const adminLoginLink = document.getElementById('adminLoginLink');
        
        if (adminControls) adminControls.style.display = 'none';
        if (uploadSection) uploadSection.style.display = 'none';
        if (publicMessage) publicMessage.style.display = 'block';
        if (adminLoginLink) {
            adminLoginLink.innerHTML = '<i class="fas fa-user-shield"></i> Admin';
            adminLoginLink.onclick = (e) => {
                e.preventDefault();
                this.showLoginModal();
            };
        }
    }
    
    showLoginModal() {
        const modal = document.getElementById('adminLoginModal');
        if (modal) {
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }
    
    hideLoginModal() {
        const modal = document.getElementById('adminLoginModal');
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
            const errorDiv = document.getElementById('adminLoginError');
            if (errorDiv) errorDiv.textContent = '';
        }
    }
    
    setupEventListeners() {
        // Admin login form
        const adminLoginForm = document.getElementById('adminLoginForm');
        if (adminLoginForm) {
            adminLoginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('adminUsername')?.value;
                const password = document.getElementById('adminPassword')?.value;
                
                if (await this.login(username, password)) {
                    this.hideLoginModal();
                    adminLoginForm.reset();
                    
                    // Refresh file list if on resources page
                    if (window.location.hash === '#resources') {
                        loadFiles();
                    }
                }
            });
        }
        
        // Admin logout button
        const logoutBtn = document.getElementById('adminLogoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.logout();
            });
        }
        
        // Request access button
        const requestBtn = document.getElementById('requestAccessBtn');
        if (requestBtn) {
            requestBtn.addEventListener('click', () => {
                this.showLoginModal();
            });
        }
        
        // Close modal buttons
        document.querySelectorAll('.close-modal').forEach(btn => {
            btn.addEventListener('click', () => {
                this.hideLoginModal();
            });
        });
        
        // Modal background click
        const modal = document.getElementById('adminLoginModal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.hideLoginModal();
                }
            });
        }
        
        // Login via navigation link
        const adminNavLink = document.getElementById('adminLoginLink');
        if (adminNavLink && !this.isAuthenticated) {
            adminNavLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showLoginModal();
            });
        }
    }
    
    requireAuth(callback) {
        if (this.isAuthenticated) {
            return callback();
        } else {
            this.showLoginModal();
            return false;
        }
    }
}

// ============================================
// FILE UPLOAD SYSTEM
// ============================================

class FileUploader {
    constructor() {
        this.selectedFiles = [];
        this.adminAuth = window.adminAuth;
        this.init();
    }
    
    init() {
        const dropArea = document.getElementById('dropArea');
        const fileInput = document.getElementById('fileInput');
        const uploadButton = document.getElementById('uploadButton');
        const cancelButton = document.getElementById('cancelUpload');
        
        if (!dropArea || !fileInput) return;
        
        // Check admin authentication
        if (!this.adminAuth?.isAuthenticated) {
            this.disableUploadArea();
            return;
        }
        
        // Enable upload area
        this.enableUploadArea();
        
        // Event listeners for drag and drop
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, this.preventDefaults, false);
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, this.highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, this.unhighlight, false);
        });
        
        dropArea.addEventListener('drop', this.handleDrop.bind(this), false);
        fileInput.addEventListener('change', this.handleFileSelect.bind(this), false);
        
        if (uploadButton) {
            uploadButton.addEventListener('click', this.handleUpload.bind(this));
        }
        
        if (cancelButton) {
            cancelButton.addEventListener('click', this.resetUpload.bind(this));
        }
    }
    
    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    highlight(e) {
        e.currentTarget.style.backgroundColor = '#e8f4fc';
        e.currentTarget.style.borderColor = '#2980b9';
    }
    
    unhighlight(e) {
        e.currentTarget.style.backgroundColor = '';
        e.currentTarget.style.borderColor = '#3498db';
    }
    
    disableUploadArea() {
        const dropArea = document.getElementById('dropArea');
        const fileInput = document.getElementById('fileInput');
        
        if (!dropArea || !fileInput) return;
        
        fileInput.disabled = true;
        dropArea.style.opacity = '0.5';
        dropArea.style.cursor = 'not-allowed';
        dropArea.innerHTML = `
            <i class="fas fa-lock"></i>
            <h3>Admin Access Required</h3>
            <p>Please login to upload files</p>
            <button class="btn btn-primary" id="loginToUpload">
                <i class="fas fa-sign-in-alt"></i> Admin Login
            </button>
        `;
        
        dropArea.querySelector('#loginToUpload')?.addEventListener('click', () => {
            this.adminAuth.showLoginModal();
        });
    }
    
    enableUploadArea() {
        const dropArea = document.getElementById('dropArea');
        const fileInput = document.getElementById('fileInput');
        
        if (!dropArea || !fileInput) return;
        
        fileInput.disabled = false;
        dropArea.style.opacity = '1';
        dropArea.style.cursor = 'pointer';
        dropArea.innerHTML = `
            <i class="fas fa-cloud-upload-alt"></i>
            <h3>Drag & Drop Files Here</h3>
            <p>or click to browse</p>
            <input type="file" id="fileInput" multiple accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.mp3,.mp4">
            <p class="file-types">Supported: PDF, DOC, JPG, PNG, MP3, MP4 (Max: 10MB)</p>
        `;
        
        // Re-attach event listener to the new input
        const newFileInput = document.getElementById('fileInput');
        if (newFileInput) {
            newFileInput.addEventListener('change', this.handleFileSelect.bind(this), false);
        }
    }
    
    handleDrop(e) {
        if (!this.adminAuth?.isAuthenticated) {
            this.adminAuth.showLoginModal();
            return;
        }
        
        const dt = e.dataTransfer;
        const files = dt.files;
        this.processFiles(files);
    }
    
    handleFileSelect(e) {
        if (!this.adminAuth?.isAuthenticated) {
            this.adminAuth.showLoginModal();
            return;
        }
        
        const files = e.target.files;
        this.processFiles(files);
    }
    
    processFiles(files) {
        // Reset
        this.selectedFiles = [];
        const fileList = document.getElementById('fileList');
        if (fileList) fileList.innerHTML = '';
        
        // Filter valid files
        const validFiles = Array.from(files).filter(file => {
            if (file.size > CONFIG.MAX_FILE_SIZE) {
                showToast(`"${file.name}" is too large (max 10MB)`, 'error');
                return false;
            }
            return true;
        });
        
        if (validFiles.length === 0) return;
        
        this.selectedFiles = validFiles;
        
        // Display files
        validFiles.forEach((file, index) => {
            this.addFileToList(file, index);
        });
        
        // Show upload details
        const uploadDetails = document.getElementById('uploadDetails');
        const uploadBox = document.getElementById('uploadBox');
        
        if (uploadDetails) {
            uploadDetails.style.display = 'block';
            uploadDetails.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        
        if (uploadBox) {
            uploadBox.style.paddingBottom = '30px';
        }
    }
    
    addFileToList(file, index) {
        const fileList = document.getElementById('fileList');
        if (!fileList) return;
        
        const extension = getFileExtension(file.name);
        const iconClass = CONFIG.FILE_ICONS[extension] || CONFIG.FILE_ICONS.default;
        
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-icon">
                <i class="${iconClass}"></i>
            </div>
            <div class="file-info">
                <div class="file-name">${file.name}</div>
                <div class="file-size">${formatFileSize(file.size)}</div>
            </div>
            <button class="file-remove" data-index="${index}">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        fileItem.querySelector('.file-remove').addEventListener('click', (e) => {
            e.stopPropagation();
            this.removeFile(index);
        });
        
        fileList.appendChild(fileItem);
    }
    
    removeFile(index) {
        this.selectedFiles.splice(index, 1);
        const fileList = document.getElementById('fileList');
        
        if (fileList) {
            fileList.innerHTML = '';
            this.selectedFiles.forEach((file, i) => {
                this.addFileToList(file, i);
            });
            
            if (this.selectedFiles.length === 0) {
                this.resetUpload();
            }
        }
    }
    
    async handleUpload() {
        if (!this.adminAuth?.isAuthenticated) {
            showToast('Please login as admin to upload files', 'error');
            this.adminAuth.showLoginModal();
            return;
        }
        
        if (this.selectedFiles.length === 0) {
            showToast('Please select files first', 'error');
            return;
        }
        
        const category = document.getElementById('fileCategory')?.value || 'other';
        const description = document.getElementById('fileDescription')?.value || '';
        const visibility = document.getElementById('uploadVisibility')?.value || 'public';
        const uploadButton = document.getElementById('uploadButton');
        
        // Show progress
        const progressBar = document.getElementById('uploadProgress');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const uploadResult = document.getElementById('uploadResult');
        
        if (progressBar) progressBar.style.display = 'block';
        if (uploadButton) uploadButton.disabled = true;
        
        const uploadText = document.getElementById('uploadText');
        const uploadLoading = document.getElementById('uploadLoading');
        
        if (uploadText) uploadText.style.display = 'none';
        if (uploadLoading) uploadLoading.style.display = 'inline';
        if (uploadResult) uploadResult.style.display = 'none';
        
        try {
            const result = await this.adminAuth.api.uploadFiles(
                this.selectedFiles, 
                category, 
                description, 
                visibility
            );
            
            if (result.success) {
                showToast(`Uploaded ${this.selectedFiles.length} file(s) successfully!`, 'success');
                this.resetUpload();
                loadFiles();
                updateStorageInfo();
            } else {
                throw new Error('Upload failed');
            }
        } catch (error) {
            console.error('Upload error:', error);
            showToast(`Upload failed: ${error.message}`, 'error');
            
            if (uploadResult) {
                uploadResult.textContent = `Error: ${error.message}`;
                uploadResult.className = 'upload-result error';
                uploadResult.style.display = 'block';
            }
        } finally {
            // Reset button state
            if (progressBar) progressBar.style.display = 'none';
            if (uploadButton) uploadButton.disabled = false;
            if (uploadText) uploadText.style.display = 'inline';
            if (uploadLoading) uploadLoading.style.display = 'none';
        }
    }
    
    resetUpload() {
        this.selectedFiles = [];
        
        const fileInput = document.getElementById('fileInput');
        const fileList = document.getElementById('fileList');
        const uploadDetails = document.getElementById('uploadDetails');
        const uploadBox = document.getElementById('uploadBox');
        const progressBar = document.getElementById('uploadProgress');
        const resultDiv = document.getElementById('uploadResult');
        const description = document.getElementById('fileDescription');
        
        if (fileInput) fileInput.value = '';
        if (fileList) fileList.innerHTML = '';
        if (uploadDetails) uploadDetails.style.display = 'none';
        if (uploadBox) uploadBox.style.paddingBottom = '30px';
        if (progressBar) progressBar.style.display = 'none';
        if (resultDiv) resultDiv.style.display = 'none';
        if (description) description.value = '';
    }
}

// ============================================
// FILE DOWNLOAD SYSTEM
// ============================================

async function loadFiles() {
    const filesGrid = document.getElementById('filesGrid');
    if (!filesGrid) return;
    
    const searchTerm = document.getElementById('searchFiles')?.value.toLowerCase() || '';
    const filterCategory = document.getElementById('filterCategory')?.value || '';
    
    // Show loading
    filesGrid.innerHTML = `
        <div class="loading-files">
            <i class="fas fa-spinner fa-spin"></i> Loading files...
        </div>
    `;
    
    try {
        const api = window.adminAuth?.api || new ApiService();
        const result = await api.getFiles(filterCategory, searchTerm);
        
        if (result.success && result.files.length > 0) {
            displayFiles(result.files);
        } else {
            showNoFilesMessage();
        }
    } catch (error) {
        console.error('Error loading files:', error);
        // Fallback to localStorage
        const files = getStoredFilesFromLocalStorage();
        displayFiles(files);
    }
}

function displayFiles(files) {
    const filesGrid = document.getElementById('filesGrid');
    if (!filesGrid) return;
    
    filesGrid.innerHTML = '';
    
    files.forEach(file => {
        filesGrid.appendChild(createFileCard(file));
    });
}

function showNoFilesMessage() {
    const filesGrid = document.getElementById('filesGrid');
    if (!filesGrid) return;
    
    const searchTerm = document.getElementById('searchFiles')?.value || '';
    const filterCategory = document.getElementById('filterCategory')?.value || '';
    
    filesGrid.innerHTML = `
        <div class="loading-files">
            <i class="fas fa-folder-open"></i>
            <p>No files found</p>
            ${searchTerm || filterCategory ? 
                '<p>Try different search terms</p>' : 
                '<p>Upload files to get started</p>'
            }
        </div>
    `;
}

function createFileCard(file) {
    const div = document.createElement('div');
    div.className = 'file-card';
    
    const iconClass = CONFIG.FILE_ICONS[file.extension] || CONFIG.FILE_ICONS.default;
    const categoryLabel = CONFIG.CATEGORY_LABELS[file.category] || 'Other';
    
    div.innerHTML = `
        <div class="file-card-icon">
            <i class="${iconClass}"></i>
        </div>
        <div class="file-card-name" title="${file.name || file.originalName}">
            ${truncateFileName(file.name || file.originalName, 20)}
        </div>
        <div class="file-card-info">
            ${formatFileSize(file.size)}
        </div>
        <div class="file-card-info">
            ${formatDate(file.uploadDate || file.createdAt)}
        </div>
        <div class="file-card-info">
            👤 ${file.uploadedBy || (file.uploader?.username || 'Church Admin')}
        </div>
        <div class="file-card-info">
            📥 ${file.downloads || file.downloadCount || 0} downloads
        </div>
        <div class="file-card-category">
            ${categoryLabel}
        </div>
        <div class="file-card-actions">
            <button class="download-btn" title="Download">
                <i class="fas fa-download"></i>
            </button>
            ${window.adminAuth?.isAuthenticated ? `
                <button class="delete-btn" title="Delete">
                    <i class="fas fa-trash"></i>
                </button>
            ` : ''}
        </div>
    `;
    
    // Event listeners
    div.addEventListener('click', (e) => {
        if (!e.target.closest('.file-card-actions')) {
            downloadFile(file);
        }
    });
    
    div.querySelector('.download-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        downloadFile(file);
    });
    
    if (window.adminAuth?.isAuthenticated) {
        div.querySelector('.delete-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            deleteFile(file.id);
        });
    }
    
    return div;
}

async function downloadFile(file) {
    try {
        const api = window.adminAuth?.api || new ApiService();
        await api.downloadFile(file);
        showToast(`Downloading "${file.name || file.originalName}"`, 'success');
        
        // Refresh file list to update download count
        setTimeout(() => {
            loadFiles();
        }, 500);
    } catch (error) {
        console.error('Download error:', error);
        showToast('Download failed', 'error');
    }
}

async function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
        return;
    }
    
    try {
        const api = window.adminAuth?.api || new ApiService();
        await api.deleteFile(fileId);
        showToast('File deleted successfully', 'success');
        loadFiles();
        updateStorageInfo();
    } catch (error) {
        console.error('Delete error:', error);
        showToast('Failed to delete file', 'error');
    }
}

function getStoredFilesFromLocalStorage() {
    const filesJson = localStorage.getItem(CONFIG.FILE_STORAGE_KEY);
    return filesJson ? JSON.parse(filesJson) : [];
}

function updateStorageInfo() {
    if (!window.adminAuth?.api?.useBackend) {
        const files = getStoredFilesFromLocalStorage();
        const totalSize = files.reduce((sum, file) => sum + (file.size || 0), 0);
        const usedMB = (totalSize / (1024 * 1024)).toFixed(2);
        const totalMB = (CONFIG.MAX_STORAGE / (1024 * 1024)).toFixed(0);
        const percentage = Math.min((totalSize / CONFIG.MAX_STORAGE) * 100, 100);
        
        const storageUsed = document.getElementById('storageUsed');
        const storageTotal = document.getElementById('storageTotal');
        const storageFill = document.getElementById('storageFill');
        
        if (storageUsed) storageUsed.textContent = `${usedMB} MB`;
        if (storageTotal) storageTotal.textContent = `${totalMB} MB`;
        if (storageFill) storageFill.style.width = `${percentage}%`;
    } else {
        // For backend, we might not have storage info easily
        const storageUsed = document.getElementById('storageUsed');
        const storageTotal = document.getElementById('storageTotal');
        const storageFill = document.getElementById('storageFill');
        
        if (storageUsed) storageUsed.textContent = 'Backend Storage';
        if (storageTotal) storageTotal.textContent = 'Unlimited';
        if (storageFill) storageFill.style.width = '30%';
    }
}

// ============================================
// PAGE NAVIGATION & MOBILE MENU
// ============================================

function toggleMenu() {
    const navMenu = document.getElementById('navMenu');
    const hamburger = document.getElementById('hamburger');
    
    if (!navMenu || !hamburger) return;
    
    navMenu.classList.toggle('active');
    hamburger.classList.toggle('active');
    
    // Prevent body scrolling when menu is open
    document.body.style.overflow = navMenu.classList.contains('active') ? 'hidden' : 'auto';
}

function showPage(pageId) {
    // Hide all pages
    const pages = document.querySelectorAll('.page-content');
    pages.forEach(page => {
        page.style.display = 'none';
    });
    
    // Show selected page
    const selectedPage = document.getElementById(pageId);
    if (selectedPage) {
        selectedPage.style.display = 'block';
    }
    
    // Update active nav link
    const navLinks = document.querySelectorAll('.nav-menu a');
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${pageId}`) {
            link.classList.add('active');
        }
    });
    
    // Scroll to top
    window.scrollTo(0, 0);
    
    // Close mobile menu if open
    const navMenu = document.getElementById('navMenu');
    const hamburger = document.getElementById('hamburger');
    if (navMenu && navMenu.classList.contains('active')) {
        navMenu.classList.remove('active');
        hamburger.classList.remove('active');
        document.body.style.overflow = 'auto';
    }
    
    // Initialize page-specific features
    if (pageId === 'resources') {
        setTimeout(() => {
            initFileSystem();
        }, 100);
    }
}

// ============================================
// FORMSPREE CONTACT FORM HANDLER
// ============================================

function initContactForm() {
    const form = document.getElementById('church-contact-form');
    if (!form) return;
    
    const status = document.getElementById('form-status');
    const submitBtn = form.querySelector('button[type="submit"]');
    
    async function handleSubmit(event) {
        event.preventDefault();
        
        // Show loading state
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
        
        if (status) {
            status.textContent = '';
            status.className = 'form-status';
        }
        
        try {
            const formData = new FormData(event.target);
            
            const response = await fetch(event.target.action, {
                method: form.method,
                body: formData,
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (response.ok) {
                if (status) {
                    status.innerHTML = '<i class="fas fa-check-circle"></i> Thank you! Your message has been sent.';
                    status.className = 'form-status success';
                }
                form.reset();
                
                // Show success message for 5 seconds
                setTimeout(() => {
                    if (status) status.textContent = '';
                }, 5000);
            } else {
                const data = await response.json();
                if (status) {
                    status.innerHTML = '<i class="fas fa-exclamation-circle"></i> ' + 
                        (data.errors ? 
                            data.errors.map(error => error.message).join(", ") : 
                            "Sorry, there was an error.");
                    status.className = 'form-status error';
                }
            }
        } catch (error) {
            if (status) {
                status.innerHTML = '<i class="fas fa-exclamation-circle"></i> Network error. Please try again.';
                status.className = 'form-status error';
            }
        } finally {
            // Reset button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }
    
    form.addEventListener('submit', handleSubmit);
}

// ============================================
// INITIALIZE FILE SYSTEM
// ============================================

function initFileSystem() {
    // Initialize upload and download systems
    window.fileUploader = new FileUploader();
    
    // Setup search and filter
    const searchInput = document.getElementById('searchFiles');
    const filterSelect = document.getElementById('filterCategory');
    
    if (searchInput) {
        searchInput.addEventListener('input', loadFiles);
    }
    
    if (filterSelect) {
        filterSelect.addEventListener('change', loadFiles);
    }
    
    // Load files and update storage info
    loadFiles();
    updateStorageInfo();
}

// ============================================
// INITIALIZE EVERYTHING ON PAGE LOAD
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Ruach Church Website Initializing...');
    
    // Show home page by default
    showPage('home');
    
    // Initialize mobile menu
    const hamburger = document.getElementById('hamburger');
    if (hamburger) {
        hamburger.addEventListener('click', toggleMenu);
    }
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        const navMenu = document.getElementById('navMenu');
        const hamburger = document.getElementById('hamburger');
        
        if (navMenu && navMenu.classList.contains('active') && 
            !navMenu.contains(event.target) && 
            !hamburger.contains(event.target)) {
            toggleMenu();
        }
    });
    
    // Close menu on window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768) {
            const navMenu = document.getElementById('navMenu');
            const hamburger = document.getElementById('hamburger');
            
            if (navMenu && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
                if (hamburger) hamburger.classList.remove('active');
                document.body.style.overflow = 'auto';
            }
        }
    });
    
    // Initialize contact form
    initContactForm();
    
    // Initialize admin authentication
    window.adminAuth = new AdminAuth();
    
    // Add CSS animations for toast
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
    
    console.log('✅ Ruach Church Website Ready!');
});

// ============================================
// WINDOW LOAD EVENT
// ============================================

window.addEventListener('load', function() {
    // Add any post-load initialization here
    document.body.classList.add('loaded');
});

// ============================================
// ERROR HANDLING
// ============================================

window.addEventListener('error', function(e) {
    console.error('Page error:', e.error);
});

// ============================================
// ADD SAMPLE FILES (FOR TESTING - FRONTEND ONLY)
// ============================================

function addSampleFiles() {
    // Only add if no files exist and backend is not available
    const api = new ApiService();
    if (api.useBackend) return;
    
    const files = getStoredFilesFromLocalStorage();
    if (files.length > 0) return;
    
    const sampleFiles = [
        {
            id: Date.now() + 1,
            name: 'Sunday_Sermon_Notes.pdf',
            size: 2457600,
            extension: 'pdf',
            category: 'sermon',
            description: 'Weekly sermon notes from Pastor',
            uploadedBy: 'Pastor Tappero',
            uploadDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
            downloads: 15
        },
        {
            id: Date.now() + 2,
            name: 'Christmas_Event_Photos.zip',
            size: 5242880,
            extension: 'zip',
            category: 'event',
            description: 'Photos from Christmas celebration',
            uploadedBy: 'Church Photographer',
            uploadDate: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
            downloads: 8
        },
        {
            id: Date.now() + 3,
            name: 'Membership_Form.docx',
            size: 102400,
            extension: 'docx',
            category: 'form',
            description: 'Church membership application form',
            uploadedBy: 'Church Office',
            uploadDate: new Date(Date.now() - 21 * 24 * 60 * 60 * 1000).toISOString(),
            downloads: 22
        }
    ];
    
    localStorage.setItem(CONFIG.FILE_STORAGE_KEY, JSON.stringify(sampleFiles));
    console.log('✅ Added sample files for frontend testing');
    
    // Refresh if on resources page
    if (window.location.hash === '#resources') {
        loadFiles();
        updateStorageInfo();
    }
}

// Uncomment to add sample files on first load (frontend only):
// addSampleFiles();

// ============================================
// HASH CHANGE HANDLER (FOR PAGE NAVIGATION)
// ============================================

window.addEventListener('hashchange', function() {
    const hash = window.location.hash.substring(1);
    if (hash) {
        showPage(hash);
    }
});

// Handle initial hash
if (window.location.hash) {
    const hash = window.location.hash.substring(1);
    showPage(hash);
}

// ============================================
// NEWS MANAGEMENT SYSTEM
// ============================================

class NewsManager {
    constructor() {
        this.currentPage = 1;
        this.itemsPerPage = 6;
        this.currentCategory = 'all';
        this.currentSort = 'newest';
        this.currentSearch = '';
        this.isAdmin = false;
        this.currentArticleId = null;
        this.init();
    }
    
    async init() {
        await this.checkAdminStatus();
        this.setupEventListeners();
        this.loadNews();
    }
    
    async checkAdminStatus() {
        try {
            const token = localStorage.getItem('church_admin_token');
            if (!token) {
                this.isAdmin = false;
                return;
            }
            
            const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.isAdmin = (data.user && (data.user.role === 'admin' || data.user.role === 'pastor'));
                
                if (this.isAdmin) {
                    document.getElementById('newsAdminControls').style.display = 'block';
                }
            }
        } catch (error) {
            this.isAdmin = false;
        }
    }
    
    setupEventListeners() {
        // Category buttons
        document.querySelectorAll('.news-category').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.setCategory(e.target.dataset.category);
            });
        });
        
        // Search input
        const searchInput = document.getElementById('newsSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.currentSearch = e.target.value;
                this.currentPage = 1;
                this.loadNews();
            });
        }
        
        // Sort select
        const sortSelect = document.getElementById('newsSort');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                this.currentSort = e.target.value;
                this.loadNews();
            });
        }
        
        // Add news button
        const addBtn = document.getElementById('addNewsBtn');
        if (addBtn) {
            addBtn.addEventListener('click', () => {
                this.openNewsModal();
            });
        }
        
        // Pagination buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('.prev-btn')) {
                this.prevPage();
            } else if (e.target.closest('.next-btn')) {
                this.nextPage();
            } else if (e.target.closest('.page-number')) {
                const page = parseInt(e.target.closest('.page-number').dataset.page);
                this.goToPage(page);
            }
        });
        
        // News modal
        const modal = document.getElementById('newsModal');
        if (modal) {
            modal.querySelectorAll('.close-modal, #cancelNewsBtn').forEach(btn => {
                btn.addEventListener('click', () => {
                    this.closeNewsModal();
                });
            });
            
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeNewsModal();
                }
            });
            
            // Editor formatting
            modal.querySelectorAll('.format-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    this.formatText(e.target.dataset.format);
                });
            });
            
            // Image preview
            const imageInput = document.getElementById('newsImage');
            if (imageInput) {
                imageInput.addEventListener('change', (e) => {
                    this.previewImage(e.target);
                });
            }
            
            // Form submission
            const form = document.getElementById('newsForm');
            if (form) {
                form.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.saveNews();
                });
            }
        }
        
        // Newsletter form
        const newsletterForm = document.getElementById('newsletterForm');
        if (newsletterForm) {
            newsletterForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.subscribeNewsletter(newsletterForm);
            });
        }
    }
    
    async loadNews() {
        const newsGrid = document.getElementById('newsGrid');
        if (!newsGrid) return;
        
        // Show loading
        newsGrid.innerHTML = `
            <div class="loading-news">
                <i class="fas fa-spinner fa-spin"></i> Loading news...
            </div>
        `;
        
        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                limit: this.itemsPerPage,
                category: this.currentCategory === 'all' ? '' : this.currentCategory,
                sort: this.currentSort,
                search: this.currentSearch
            });
            
            const response = await fetch(`${API_BASE_URL}/news?${params}`);
            
            if (response.ok) {
                const data = await response.json();
                this.displayNews(data.articles);
                this.updatePagination(data.total, data.totalPages);
            } else {
                // Fallback to sample data
                this.displaySampleNews();
            }
        } catch (error) {
            console.error('Error loading news:', error);
            this.displaySampleNews();
        }
    }
    
    displayNews(articles) {
        const newsGrid = document.getElementById('newsGrid');
        if (!newsGrid) return;
        
        if (!articles || articles.length === 0) {
            newsGrid.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-newspaper"></i>
                    <h3>No news articles found</h3>
                    <p>${this.currentSearch ? 'Try a different search term' : 'Check back later for updates'}</p>
                    ${this.isAdmin ? '<button class="btn btn-primary" id="addFirstNewsBtn">Add First Article</button>' : ''}
                </div>
            `;
            
            const addFirstBtn = document.getElementById('addFirstNewsBtn');
            if (addFirstBtn) {
                addFirstBtn.addEventListener('click', () => this.openNewsModal());
            }
            return;
        }
        
        newsGrid.innerHTML = articles.map(article => `
            <div class="news-card" data-id="${article._id}">
                ${article.featured ? '<span class="featured-badge">⭐ Featured</span>' : ''}
                
                ${this.isAdmin ? `
                    <div class="news-admin-actions">
                        <button class="admin-action-btn edit-btn" onclick="newsManager.editNews('${article._id}')">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="admin-action-btn delete-btn" onclick="newsManager.deleteNews('${article._id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                ` : ''}
                
                <div class="news-image">
                    ${article.image ? 
                        `<img src="${API_BASE_URL}/uploads/${article.image}" alt="${article.title}" class="news-image">` :
                        `<i class="fas fa-newspaper"></i>`
                    }
                </div>
                
                <div class="news-content">
                    <span class="news-category-badge">${this.getCategoryLabel(article.category)}</span>
                    <h3 class="news-title">${article.title}</h3>
                    <p class="news-excerpt">${article.excerpt || article.content.substring(0, 150)}...</p>
                    <div class="news-meta">
                        <span class="news-date">
                            <i class="far fa-calendar"></i>
                            ${new Date(article.date).toLocaleDateString()}
                        </span>
                        <span class="news-views">
                            <i class="far fa-eye"></i>
                            ${article.views || 0}
                        </span>
                    </div>
                </div>
            </div>
        `).join('');
        
        // Add click events to news cards
        newsGrid.querySelectorAll('.news-card').forEach(card => {
            card.addEventListener('click', (e) => {
                if (!e.target.closest('.news-admin-actions')) {
                    const articleId = card.dataset.id;
                    this.viewNewsDetail(articleId);
                }
            });
        });
    }
    
    displaySampleNews() {
        const sampleNews = [
            {
                _id: '1',
                title: 'Christmas Celebration 2025',
                excerpt: 'Join us for our annual Christmas celebration with special music, drama, and fellowship.',
                category: 'events',
                date: new Date('2025-12-20'),
                views: 45,
                featured: true
            },
            {
                _id: '2',
                title: 'New Youth Ministry Launch',
                excerpt: 'Exciting new youth ministry program starting this month for teens and young adults.',
                category: 'ministries',
                date: new Date('2025-12-15'),
                views: 32
            },
            {
                _id: '3',
                title: 'Sunday Service Time Update',
                excerpt: 'Important announcement about updated service times starting in January.',
                category: 'announcements',
                date: new Date('2025-12-10'),
                views: 28
            }
        ];
        
        this.displayNews(sampleNews);
    }
    
    getCategoryLabel(category) {
        const labels = {
            'announcements': 'Announcement',
            'events': 'Event',
            'ministries': 'Ministry',
            'testimonies': 'Testimony',
            'general': 'General'
        };
        return labels[category] || 'News';
    }
    
    updatePagination(total, totalPages) {
        const pagination = document.getElementById('newsPagination');
        const pageNumbers = document.getElementById('pageNumbers');
        
        if (!pagination || !pageNumbers) return;
        
        if (totalPages <= 1) {
            pagination.style.display = 'none';
            return;
        }
        
        pagination.style.display = 'flex';
        
        // Update page numbers
        pageNumbers.innerHTML = '';
        for (let i = 1; i <= totalPages; i++) {
            const pageBtn = document.createElement('span');
            pageBtn.className = `page-number ${i === this.currentPage ? 'active' : ''}`;
            pageBtn.textContent = i;
            pageBtn.dataset.page = i;
            pageNumbers.appendChild(pageBtn);
        }
        
        // Update button states
        const prevBtn = pagination.querySelector('.prev-btn');
        const nextBtn = pagination.querySelector('.next-btn');
        
        prevBtn.disabled = this.currentPage === 1;
        nextBtn.disabled = this.currentPage === totalPages;
    }
    
    setCategory(category) {
        this.currentCategory = category;
        this.currentPage = 1;
        
        // Update active category button
        document.querySelectorAll('.news-category').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.category === category) {
                btn.classList.add('active');
            }
        });
        
        this.loadNews();
    }
    
    prevPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.loadNews();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }
    
    nextPage() {
        this.currentPage++;
        this.loadNews();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    
    goToPage(page) {
        this.currentPage = page;
        this.loadNews();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    
    openNewsModal(articleId = null) {
        const modal = document.getElementById('newsModal');
        const modalTitle = document.getElementById('modalTitle');
        const form = document.getElementById('newsForm');
        
        if (!modal || !modalTitle || !form) return;
        
        this.currentArticleId = articleId;
        
        if (articleId) {
            modalTitle.textContent = 'Edit News Article';
            this.loadArticleForEditing(articleId);
        } else {
            modalTitle.textContent = 'Add News Article';
            form.reset();
            document.getElementById('newsContent').innerHTML = '';
            document.getElementById('imagePreview').style.display = 'none';
            document.getElementById('newsId').value = '';
        }
        
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
    
    closeNewsModal() {
        const modal = document.getElementById('newsModal');
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }
    
    async loadArticleForEditing(articleId) {
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${API_BASE_URL}/news/${articleId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                const article = await response.json();
                
                // Fill form fields
                document.getElementById('newsId').value = article._id;
                document.getElementById('newsTitle').value = article.title;
                document.getElementById('newsCategory').value = article.category;
                document.getElementById('newsAuthor').value = article.author || '';
                document.getElementById('newsTags').value = article.tags ? article.tags.join(', ') : '';
                document.getElementById('newsFeatured').checked = article.featured || false;
                document.getElementById('newsPublished').checked = article.published || false;
                document.getElementById('newsContent').innerHTML = article.content || '';
                
                if (article.image) {
                    const preview = document.getElementById('imagePreview');
                    const previewImg = document.getElementById('previewImg');
                    previewImg.src = `${API_BASE_URL}/uploads/${article.image}`;
                    preview.style.display = 'block';
                }
            }
        } catch (error) {
            console.error('Error loading article:', error);
            showToast('Failed to load article', 'error');
        }
    }
    
    formatText(format) {
        const editor = document.getElementById('newsContent');
        if (!editor) return;
        
        document.execCommand(format, false, null);
        editor.focus();
    }
    
    previewImage(input) {
        const preview = document.getElementById('imagePreview');
        const previewImg = document.getElementById('previewImg');
        
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                previewImg.src = e.target.result;
                preview.style.display = 'block';
            };
            
            reader.readAsDataURL(input.files[0]);
        }
    }
    
    async saveNews() {
        const form = document.getElementById('newsForm');
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }
        
        const formData = new FormData(form);
        const content = document.getElementById('newsContent').innerHTML;
        const imageFile = document.getElementById('newsImage').files[0];
        
        formData.append('content', content);
        if (imageFile) {
            formData.append('image', imageFile);
        }
        
        const articleId = document.getElementById('newsId').value;
        const method = articleId ? 'PUT' : 'POST';
        const url = articleId ? `${API_BASE_URL}/news/${articleId}` : `${API_BASE_URL}/news`;
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(url, {
                method: method,
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });
            
            if (response.ok) {
                showToast(`Article ${articleId ? 'updated' : 'created'} successfully!`, 'success');
                this.closeNewsModal();
                this.loadNews();
            } else {
                throw new Error('Failed to save article');
            }
        } catch (error) {
            console.error('Save article error:', error);
            showToast('Failed to save article', 'error');
        }
    }
    
    async viewNewsDetail(articleId) {
        try {
            const response = await fetch(`${API_BASE_URL}/news/${articleId}`);
            
            if (response.ok) {
                const article = await response.json();
                this.displayNewsDetail(article);
            } else {
                // Fallback to sample detail
                this.displaySampleDetail(articleId);
            }
        } catch (error) {
            console.error('Error loading news detail:', error);
            this.displaySampleDetail(articleId);
        }
    }
    
    displayNewsDetail(article) {
        const modal = document.getElementById('newsDetailModal');
        const content = document.getElementById('newsDetailContent');
        
        if (!modal || !content) return;
        
        content.innerHTML = `
            <div class="news-detail">
                <div class="news-detail-header">
                    <span class="news-detail-category">${this.getCategoryLabel(article.category)}</span>
                    <h1 class="news-detail-title">${article.title}</h1>
                    <div class="news-detail-meta">
                        <span><i class="far fa-calendar"></i> ${new Date(article.date).toLocaleDateString()}</span>
                        <span><i class="far fa-user"></i> ${article.author || 'Church Admin'}</span>
                        <span><i class="far fa-eye"></i> ${article.views || 0} views</span>
                    </div>
                </div>
                
                ${article.image ? `
                    <img src="${API_BASE_URL}/uploads/${article.image}" alt="${article.title}" class="news-detail-image">
                ` : ''}
                
                <div class="news-detail-content">
                    ${article.content}
                </div>
                
                ${article.tags && article.tags.length > 0 ? `
                    <div class="news-detail-footer">
                        <div class="news-tags">
                            ${article.tags.map(tag => `<span class="news-tag">#${tag}</span>`).join('')}
                        </div>
                        <div class="share-buttons">
                            <button class="btn btn-outline" onclick="newsManager.shareArticle('${article._id}')">
                                <i class="fas fa-share-alt"></i> Share
                            </button>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
        
        // Update view count
        this.incrementViewCount(article._id);
        
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        
        // Close modal on X click
        modal.querySelector('.close-modal').addEventListener('click', () => {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        });
        
        // Close modal on outside click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        });
    }
    
    displaySampleDetail(articleId) {
        const sampleDetails = {
            '1': {
                title: 'Christmas Celebration 2025',
                category: 'events',
                date: '2025-12-20',
                author: 'Pastor Tappero',
                views: 45,
                content: `
                    <h2>Join Us for a Memorable Christmas Celebration</h2>
                    <p>We are excited to invite you to our annual Christmas celebration on December 25, 2025. This year's theme is "The Light of the World" based on John 8:12.</p>
                    
                    <h3>Event Details:</h3>
                    <ul>
                        <li>Date: December 25, 2025</li>
                        <li>Time: 7:00 PM - 9:00 PM</li>
                        <li>Location: Main Sanctuary</li>
                        <li>Dress: Christmas colors encouraged!</li>
                    </ul>
                    
                    <h3>Special Features:</h3>
                    <p>Our celebration will include:</p>
                    <ul>
                        <li>Special Christmas choir performance</li>
                        <li>Children's nativity play</li>
                        <li>Traditional carols and contemporary worship</li>
                        <li>Message from Pastor Tappero</li>
                        <li>Fellowship dinner after service</li>
                    </ul>
                    
                    <p>This is a family-friendly event perfect for inviting friends and neighbors who want to experience the true meaning of Christmas.</p>
                    
                    <p><strong>Note:</strong> Please bring a dessert to share for the fellowship time after the service.</p>
                `,
                tags: ['christmas', 'celebration', 'family', 'worship']
            },
            '2': {
                title: 'New Youth Ministry Launch',
                category: 'ministries',
                date: '2025-12-15',
                author: 'Youth Pastor',
                views: 32,
                content: `
                    <h2>Exciting News for Our Youth!</h2>
                    <p>We are thrilled to announce the launch of our revamped Youth Ministry program starting January 2026!</p>
                    
                    <h3>New Program Features:</h3>
                    <ul>
                        <li><strong>Friday Night Youth Group:</strong> Weekly gatherings for teens (ages 13-18)</li>
                        <li><strong>Small Groups:</strong> Age-appropriate Bible study groups</li>
                        <li><strong>Service Projects:</strong> Monthly community outreach opportunities</li>
                        <li><strong>Mentorship Program:</strong> One-on-one discipleship with adult leaders</li>
                    </ul>
                    
                    <h3>Schedule:</h3>
                    <p><strong>Fridays: 7:00 PM - 9:00 PM</strong><br>
                    Youth Center (Room 201)</p>
                    
                    <h3>Meet Our Youth Leaders:</h3>
                    <p>Our dedicated team of youth leaders has been trained and is excited to connect with our young people. They bring experience, passion, and a heart for youth discipleship.</p>
                    
                    <p><strong>Registration:</strong> All youth are welcome! No registration fee. Please contact the church office to sign up.</p>
                    
                    <p>Parents: We will have an information meeting on December 30th at 6:00 PM to answer questions and share our vision for youth ministry.</p>
                `,
                tags: ['youth', 'ministry', 'teens', 'discipleship']
            }
        };
        
        const article = sampleDetails[articleId] || sampleDetails['1'];
        this.displayNewsDetail(article);
    }
    
    async incrementViewCount(articleId) {
        try {
            await fetch(`${API_BASE_URL}/news/${articleId}/view`, {
                method: 'POST'
            });
        } catch (error) {
            // Silent fail - views are not critical
        }
    }
    
    async editNews(articleId) {
        event.stopPropagation();
        this.openNewsModal(articleId);
    }
    
    async deleteNews(articleId) {
        event.stopPropagation();
        
        if (!confirm('Are you sure you want to delete this news article? This action cannot be undone.')) {
            return;
        }
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${API_BASE_URL}/news/${articleId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                showToast('Article deleted successfully', 'success');
                this.loadNews();
            } else {
                throw new Error('Failed to delete article');
            }
        } catch (error) {
            console.error('Delete article error:', error);
            showToast('Failed to delete article', 'error');
        }
    }
    
    async shareArticle(articleId) {
        const articleUrl = `${window.location.origin}${window.location.pathname}#news/${articleId}`;
        
        if (navigator.share) {
            try {
                await navigator.share({
                    title: document.title,
                    text: 'Check out this news article from Ruach Church',
                    url: articleUrl
                });
            } catch (error) {
                // Fallback to copy to clipboard
                this.copyToClipboard(articleUrl);
            }
        } else {
            this.copyToClipboard(articleUrl);
        }
    }
    
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Link copied to clipboard!', 'success');
        });
    }
    
    async subscribeNewsletter(form) {
        const email = form.querySelector('input[type="email"]').value;
        
        try {
            const response = await fetch(`${API_BASE_URL}/newsletter/subscribe`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            
            if (response.ok) {
                showToast('Thank you for subscribing to our newsletter!', 'success');
                form.reset();
            } else {
                showToast('Subscription failed. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Newsletter subscription error:', error);
            showToast('Subscribed successfully!', 'success');
            form.reset();
        }
    }
}

// Initialize news manager when page loads
let newsManager = null;

document.addEventListener('DOMContentLoaded', () => {
    newsManager = new NewsManager();
});

// Update showPage function to handle news page
const originalShowPage = window.showPage;
window.showPage = function(pageId) {
    originalShowPage(pageId);
    
    if (pageId === 'news' && newsManager) {
        newsManager.loadNews();
    }
};
// Load news on homepage
async function loadHomepageNews() {
    try {
        const response = await fetch(`${API_BASE_URL}/news/recent`);
        const container = document.getElementById('homeNews');
        
        if (!container) return;
        
        if (response.ok) {
            const data = await response.json();
            displayHomepageNews(data.articles);
        }
    } catch (error) {
        console.error('Error loading homepage news:', error);
    }
}

function displayHomepageNews(articles) {
    const container = document.getElementById('homeNews');
    if (!container || !articles || articles.length === 0) {
        container.innerHTML = '<p>No news available</p>';
        return;
    }
    
    container.innerHTML = `
        <div class="news-grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
            ${articles.map(article => `
                <div class="news-card" onclick="newsManager.viewNewsDetail('${article._id}')">
                    <div class="news-image">
                        ${article.image ? 
                            `<img src="${API_BASE_URL}/uploads/${article.image}" alt="${article.title}">` :
                            `<i class="fas fa-newspaper"></i>`
                        }
                    </div>
                    <div class="news-content">
                        <span class="news-category-badge">${newsManager.getCategoryLabel(article.category)}</span>
                        <h3 class="news-title">${article.title}</h3>
                        <p class="news-excerpt">${article.excerpt || article.content.substring(0, 100)}...</p>
                        <div class="news-meta">
                            <span class="news-date">
                                <i class="far fa-calendar"></i>
                                ${new Date(article.date).toLocaleDateString()}
                            </span>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

// Call when homepage loads
if (window.location.hash === '#home' || !window.location.hash) {
    setTimeout(loadHomepageNews, 500);
}
// ============================================
// ADMIN PANEL SYSTEM
// ============================================

class AdminPanel {
    constructor() {
        this.currentPage = null;
        this.currentSection = null;
        this.isInitialized = false;
        this.apiBaseUrl = 'http://localhost:5000/api';
    }
    
    async init() {
        if (this.isInitialized) return;
        
        this.checkAdminStatus();
        this.createAdminPanelHTML();
        this.setupEventListeners();
        this.loadSiteSettings();
        
        this.isInitialized = true;
    }
    
    async checkAdminStatus() {
        const token = localStorage.getItem('church_admin_token');
        if (!token) {
            this.hideAdminPanel();
            return false;
        }
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/verify`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.valid && (data.user.role === 'admin' || data.user.role === 'pastor')) {
                    this.showAdminPanel();
                    this.currentUser = data.user;
                    return true;
                }
            }
        } catch (error) {
            console.error('Admin status check failed:', error);
        }
        
        this.hideAdminPanel();
        return false;
    }
    
    createAdminPanelHTML() {
        // Remove existing admin panel if any
        const existingPanel = document.getElementById('adminPanel');
        if (existingPanel) existingPanel.remove();
        
        const adminPanelHTML = `
            <div id="adminPanel" style="display: none;">
                <button id="adminPanelBtn" class="admin-float-btn">
                    <i class="fas fa-cog"></i> Admin
                </button>
                
                <div id="adminPanelModal" class="admin-modal">
                    <div class="admin-modal-content">
                        <div class="admin-modal-header">
                            <h3><i class="fas fa-user-shield"></i> Admin Control Panel</h3>
                            <span class="admin-close-modal">&times;</span>
                        </div>
                        
                        <div class="admin-modal-body">
                            <div class="admin-tabs">
                                <button class="admin-tab active" data-tab="pages">📄 Edit Pages</button>
                                <button class="admin-tab" data-tab="content">✏️ Edit Content</button>
                                <button class="admin-tab" data-tab="settings">⚙️ Site Settings</button>
                                <button class="admin-tab" data-tab="stats">📊 Statistics</button>
                            </div>
                            
                            <div id="pages-tab" class="admin-tab-content active">
                                <h4>Edit Page Content</h4>
                                <div class="form-group">
                                    <label>Select Page:</label>
                                    <select id="pageSelector" class="form-control">
                                        <option value="home">🏠 Home Page</option>
                                        <option value="about">📖 About Page</option>
                                        <option value="ministries">🙏 Ministries Page</option>
                                        <option value="events">📅 Events Page</option>
                                        <option value="resources">📚 Resources Page</option>
                                        <option value="news">📰 News Page</option>
                                        <option value="contact">📞 Contact Page</option>
                                    </select>
                                </div>
                                
                                <div id="pageEditor">
                                    <p>Select a page to edit its content</p>
                                </div>
                            </div>
                            
                            <div id="content-tab" class="admin-tab-content">
                                <h4>Edit Text Content</h4>
                                <div class="form-group">
                                    <label>Page Element:</label>
                                    <select id="contentSelector" class="form-control">
                                        <option value="">Select an element...</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label>Content:</label>
                                    <textarea id="contentEditor" class="form-control" rows="6" placeholder="Enter content..."></textarea>
                                </div>
                                
                                <button id="saveContentBtn" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Save Changes
                                </button>
                                <button id="previewContentBtn" class="btn btn-outline">
                                    <i class="fas fa-eye"></i> Preview
                                </button>
                            </div>
                            
                            <div id="settings-tab" class="admin-tab-content">
                                <h4>Site Settings</h4>
                                <div id="settingsList">
                                    <div class="loading-settings">
                                        <i class="fas fa-spinner fa-spin"></i> Loading settings...
                                    </div>
                                </div>
                            </div>
                            
                            <div id="stats-tab" class="admin-tab-content">
                                <h4>Website Statistics</h4>
                                <div class="stats-grid">
                                    <div class="stat-card">
                                        <i class="fas fa-users"></i>
                                        <h3 id="totalVisitors">0</h3>
                                        <p>Total Visitors</p>
                                    </div>
                                    <div class="stat-card">
                                        <i class="fas fa-download"></i>
                                        <h3 id="totalDownloads">0</h3>
                                        <p>File Downloads</p>
                                    </div>
                                    <div class="stat-card">
                                        <i class="fas fa-newspaper"></i>
                                        <h3 id="totalArticles">0</h3>
                                        <p>News Articles</p>
                                    </div>
                                    <div class="stat-card">
                                        <i class="fas fa-file-upload"></i>
                                        <h3 id="totalFiles">0</h3>
                                        <p>Uploaded Files</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="admin-modal-footer">
                            <button id="adminLogoutBtn" class="btn btn-outline">
                                <i class="fas fa-sign-out-alt"></i> Logout
                            </button>
                            <button id="saveAllBtn" class="btn btn-success">
                                <i class="fas fa-save"></i> Save All Changes
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', adminPanelHTML);
    }
    
    setupEventListeners() {
        // Floating button
        const adminPanelBtn = document.getElementById('adminPanelBtn');
        const adminModal = document.getElementById('adminPanelModal');
        const closeModal = document.querySelector('.admin-close-modal');
        
        adminPanelBtn?.addEventListener('click', () => {
            adminModal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        });
        
        closeModal?.addEventListener('click', () => {
            adminModal.style.display = 'none';
            document.body.style.overflow = 'auto';
        });
        
        // Close modal on outside click
        window.addEventListener('click', (e) => {
            if (e.target === adminModal) {
                adminModal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        });
        
        // Tab switching
        document.querySelectorAll('.admin-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchTab(tabName);
            });
        });
        
        // Page selector
        const pageSelector = document.getElementById('pageSelector');
        pageSelector?.addEventListener('change', (e) => {
            this.loadPageContent(e.target.value);
        });
        
        // Save content button
        const saveContentBtn = document.getElementById('saveContentBtn');
        saveContentBtn?.addEventListener('click', () => {
            this.saveContent();
        });
        
        // Save all button
        const saveAllBtn = document.getElementById('saveAllBtn');
        saveAllBtn?.addEventListener('click', () => {
            this.saveAllChanges();
        });
        
        // Logout button
        const logoutBtn = document.getElementById('adminLogoutBtn');
        logoutBtn?.addEventListener('click', () => {
            this.logout();
        });
        
        // Content selector
        const contentSelector = document.getElementById('contentSelector');
        contentSelector?.addEventListener('change', (e) => {
            this.loadElementContent(e.target.value);
        });
    }
    
    showAdminPanel() {
        const adminPanel = document.getElementById('adminPanel');
        if (adminPanel) {
            adminPanel.style.display = 'block';
        }
    }
    
    hideAdminPanel() {
        const adminPanel = document.getElementById('adminPanel');
        if (adminPanel) {
            adminPanel.style.display = 'none';
        }
    }
    
    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.admin-tab').forEach(tab => {
            tab.classList.remove('active');
            if (tab.dataset.tab === tabName) {
                tab.classList.add('active');
            }
        });
        
        // Show active content
        document.querySelectorAll('.admin-tab-content').forEach(content => {
            content.classList.remove('active');
        });
        
        const activeContent = document.getElementById(`${tabName}-tab`);
        if (activeContent) {
            activeContent.classList.add('active');
        }
        
        // Load data for the tab
        if (tabName === 'stats') {
            this.loadStatistics();
        } else if (tabName === 'settings') {
            this.loadSiteSettings();
        }
    }
    
    async loadPageContent(pageId) {
        this.currentPage = pageId;
        const pageEditor = document.getElementById('pageEditor');
        
        if (!pageEditor) return;
        
        pageEditor.innerHTML = `
            <div class="loading-page">
                <i class="fas fa-spinner fa-spin"></i> Loading page content...
            </div>
        `;
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${this.apiBaseUrl}/pages/${pageId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayPageEditor(data.page);
            } else {
                pageEditor.innerHTML = `
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Failed to load page content</p>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Load page error:', error);
            pageEditor.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Error loading page: ${error.message}</p>
                </div>
            `;
        }
    }
    
    displayPageEditor(page) {
        const pageEditor = document.getElementById('pageEditor');
        if (!pageEditor) return;
        
        let content = `
            <h4>${page.title} - Sections</h4>
            <div class="page-sections">
        `;
        
        if (page.sections && page.sections.length > 0) {
            page.sections.forEach(section => {
                content += `
                    <div class="section-item" data-section-id="${section.sectionId}">
                        <div class="section-header">
                            <h5>${section.sectionId.replace(/_/g, ' ')}</h5>
                            <button class="btn btn-small btn-primary edit-section-btn" 
                                    data-section-id="${section.sectionId}">
                                <i class="fas fa-edit"></i> Edit
                            </button>
                        </div>
                        <div class="section-preview">
                            ${typeof section.content === 'string' ? 
                                section.content.substring(0, 100) + '...' : 
                                '[Complex Content]'}
                        </div>
                    </div>
                `;
            });
        } else {
            content += `<p>No sections found. Sections will be created as you edit content.</p>`;
        }
        
        content += `
            </div>
            <div class="add-section">
                <h5>Add New Section</h5>
                <div class="form-group">
                    <label>Section ID:</label>
                    <input type="text" id="newSectionId" class="form-control" 
                           placeholder="e.g., hero_title, welcome_message">
                </div>
                <div class="form-group">
                    <label>Content:</label>
                    <textarea id="newSectionContent" class="form-control" rows="4"></textarea>
                </div>
                <button id="addSectionBtn" class="btn btn-primary">
                    <i class="fas fa-plus"></i> Add Section
                </button>
            </div>
        `;
        
        pageEditor.innerHTML = content;
        
        // Add event listeners for edit buttons
        pageEditor.querySelectorAll('.edit-section-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const sectionId = e.target.closest('.edit-section-btn').dataset.sectionId;
                this.editSection(sectionId);
            });
        });
        
        // Add new section button
        const addSectionBtn = document.getElementById('addSectionBtn');
        addSectionBtn?.addEventListener('click', () => {
            this.addNewSection();
        });
    }
    
    editSection(sectionId) {
        this.currentSection = sectionId;
        this.switchTab('content');
        
        // Update content selector
        const contentSelector = document.getElementById('contentSelector');
        contentSelector.value = sectionId;
        
        // Load the content
        this.loadElementContent(sectionId);
    }
    
    async loadElementContent(elementId) {
        if (!this.currentPage || !elementId) return;
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${this.apiBaseUrl}/pages/${this.currentPage}/sections/${elementId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            const contentEditor = document.getElementById('contentEditor');
            
            if (response.ok) {
                const data = await response.json();
                contentEditor.value = typeof data.content === 'string' ? 
                    data.content : 
                    JSON.stringify(data.content, null, 2);
            } else {
                contentEditor.value = '';
            }
        } catch (error) {
            console.error('Load element error:', error);
            document.getElementById('contentEditor').value = '';
        }
    }
    
    async saveContent() {
        const sectionId = document.getElementById('contentSelector')?.value;
        const content = document.getElementById('contentEditor')?.value;
        
        if (!sectionId || !content || !this.currentPage) {
            showToast('Please select a section and enter content', 'error');
            return;
        }
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${this.apiBaseUrl}/pages/${this.currentPage}/sections/${sectionId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content, type: 'text' })
            });
            
            if (response.ok) {
                showToast('Content saved successfully!', 'success');
                this.loadPageContent(this.currentPage);
                
                // Update live website if on the same page
                this.updateLiveContent(sectionId, content);
            } else {
                throw new Error('Save failed');
            }
        } catch (error) {
            console.error('Save content error:', error);
            showToast('Failed to save content', 'error');
        }
    }
    
    updateLiveContent(sectionId, content) {
        // This function updates the live website without refresh
        const currentPage = window.location.hash.substring(1) || 'home';
        if (currentPage !== this.currentPage) return;
        
        // Map section IDs to DOM selectors
        const selectors = {
            'hero_title': '.hero h1',
            'hero_subtitle': '.hero p',
            'welcome_message': '.welcome-text p',
            'pastor_message': '.pastor-message .quote',
            'mission': '.service-card:nth-child(1) p',
            'vision': '.service-card:nth-child(2) p',
            'service_times': '.service-time'
        };
        
        const selector = selectors[sectionId];
        if (selector) {
            const element = document.querySelector(selector);
            if (element) {
                element.textContent = content;
            }
        }
    }
    
    async addNewSection() {
        const sectionId = document.getElementById('newSectionId')?.value;
        const content = document.getElementById('newSectionContent')?.value;
        
        if (!sectionId || !content || !this.currentPage) {
            showToast('Please enter section ID and content', 'error');
            return;
        }
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${this.apiBaseUrl}/pages/${this.currentPage}/sections/${sectionId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content, type: 'text' })
            });
            
            if (response.ok) {
                showToast('Section added successfully!', 'success');
                this.loadPageContent(this.currentPage);
                
                // Clear form
                document.getElementById('newSectionId').value = '';
                document.getElementById('newSectionContent').value = '';
            } else {
                throw new Error('Add section failed');
            }
        } catch (error) {
            console.error('Add section error:', error);
            showToast('Failed to add section', 'error');
        }
    }
    
    async loadSiteSettings() {
        const settingsList = document.getElementById('settingsList');
        if (!settingsList) return;
        
        settingsList.innerHTML = `
            <div class="loading-settings">
                <i class="fas fa-spinner fa-spin"></i> Loading settings...
            </div>
        `;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/settings`);
            
            if (response.ok) {
                const data = await response.json();
                this.displaySettings(data.settings);
            }
        } catch (error) {
            console.error('Load settings error:', error);
            settingsList.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Failed to load settings</p>
                </div>
            `;
        }
    }
    
    displaySettings(settings) {
        const settingsList = document.getElementById('settingsList');
        if (!settingsList) return;
        
        let content = '<div class="settings-grid">';
        
        Object.entries(settings).forEach(([key, value]) => {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            content += `
                <div class="setting-item">
                    <label for="setting_${key}">${label}:</label>
                    <div class="setting-input">
                        ${typeof value === 'boolean' ? 
                            `<input type="checkbox" id="setting_${key}" ${value ? 'checked' : ''}>` :
                            `<input type="${typeof value}" id="setting_${key}" value="${value}" 
                                   class="form-control">`
                        }
                    </div>
                    <button class="btn btn-small btn-primary save-setting-btn" data-key="${key}">
                        <i class="fas fa-save"></i>
                    </button>
                </div>
            `;
        });
        
        content += '</div>';
        settingsList.innerHTML = content;
        
        // Add event listeners for save buttons
        settingsList.querySelectorAll('.save-setting-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const key = e.target.closest('.save-setting-btn').dataset.key;
                this.saveSetting(key);
            });
        });
    }
    
    async saveSetting(key) {
        const input = document.getElementById(`setting_${key}`);
        if (!input) return;
        
        let value;
        if (input.type === 'checkbox') {
            value = input.checked;
        } else if (input.type === 'number') {
            value = parseFloat(input.value);
        } else {
            value = input.value;
        }
        
        try {
            const token = localStorage.getItem('church_admin_token');
            const response = await fetch(`${this.apiBaseUrl}/settings/${key}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ value })
            });
            
            if (response.ok) {
                showToast(`Setting "${key}" updated`, 'success');
                
                // Update live website if applicable
                this.updateLiveSetting(key, value);
            } else {
                throw new Error('Save failed');
            }
        } catch (error) {
            console.error('Save setting error:', error);
            showToast('Failed to save setting', 'error');
        }
    }
    
    updateLiveSetting(key, value) {
        // Update specific elements on the live website
        const updates = {
            'church_name': () => {
                document.querySelectorAll('.logo span').forEach(el => el.textContent = value);
            },
            'church_address': () => {
                document.querySelectorAll('.contact-details p, .footer-col p').forEach(el => {
                    if (el.textContent.includes('2274')) el.textContent = value;
                });
            },
            'church_phone': () => {
                document.querySelectorAll('.contact-item p').forEach(el => {
                    if (el.textContent.includes('470')) el.textContent = value;
                });
            },
            'service_times_sunday': () => {
                document.querySelectorAll('.service-time').forEach(el => {
                    if (el.textContent.includes('3:00')) el.textContent = value;
                });
            }
        };
        
        if (updates[key]) {
            updates[key]();
        }
    }
    
    async loadStatistics() {
        try {
            const token = localStorage.getItem('church_admin_token');
            
            // Load files count
            const filesResponse = await fetch(`${this.apiBaseUrl}/files?limit=1`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const filesData = await filesResponse.json();
            
            // Load news count
            const newsResponse = await fetch(`${this.apiBaseUrl}/news?limit=1`);
            const newsData = await newsResponse.json();
            
            // Update statistics display
            document.getElementById('totalFiles').textContent = filesData.total || 0;
            document.getElementById('totalArticles').textContent = newsData.total || 0;
            
            // For demo purposes, use sample data
            document.getElementById('totalVisitors').textContent = '';
            document.getElementById('totalDownloads').textContent = '';
            
        } catch (error) {
            console.error('Load statistics error:', error);
        }
    }
    
    async saveAllChanges() {
        showToast('All changes have been saved!', 'success');
    }
    
    logout() {
        localStorage.removeItem('church_admin_token');
        localStorage.removeItem('church_admin_user');
        this.hideAdminPanel();
        window.adminAuth.logout();
        showToast('Logged out successfully', 'success');
        
        // Close admin modal
        const adminModal = document.getElementById('adminPanelModal');
        if (adminModal) {
            adminModal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }
}

// Initialize Admin Panel
let adminPanel = null;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize admin panel after a short delay
    setTimeout(() => {
        adminPanel = new AdminPanel();
        adminPanel.init();
    }, 1000);
    
    // Check for admin authentication on page changes
    window.addEventListener('hashchange', () => {
        if (adminPanel) {
            adminPanel.checkAdminStatus();
        }
    });
});
// ===== NEWS MANAGEMENT SYSTEM =====

// News data storage (in a real app, this would come from a backend)
let newsData = [
    {
        id: 1,
        title: "Watchnight Service",
        category: "events",
        content: "<p>Join us as we pray in the New Year with worship, testimonies, and prayer. This special service starts at 7:00 PM and continues until midnight.</p><p>Bring your family and friends for a night of celebration and prayer.</p>",
        excerpt: "Join us as we pray in the New Year with worship, testimonies, and prayer.",
        date: "2025-12-31",
        author: "Pastor Tappero",
        tags: ["new year", "prayer", "worship"],
        views: 45,
        featured: true,
        image: "IMAGES/christmas.jpg",
        published: true
    },
    {
        id: 2,
        title: "Christmas Celebration",
        category: "events",
        content: "<p>Join us for our annual Christmas celebration featuring our choir and special guest musicians. This family-friendly event includes traditional carols, contemporary Christmas music, and a special message of hope.</p>",
        excerpt: "Annual Christmas celebration with choir and special music.",
        date: "2025-12-25",
        author: "Church Staff",
        tags: ["christmas", "celebration", "family"],
        views: 32,
        featured: true,
        image: "IMAGES/christmas.jpg",
        published: true
    },
    {
        id: 3,
        title: "Youth Ministry Launch",
        category: "ministries",
        content: "<p>We're excited to announce the launch of our new Youth Ministry program! Starting this Friday, we'll have dynamic gatherings with worship, relevant teaching, and authentic community for teens.</p>",
        excerpt: "New Youth Ministry program launching this Friday.",
        date: "2025-12-01",
        author: "Youth Leader",
        tags: ["youth", "ministry", "launch"],
        views: 28,
        featured: false,
        image: "https://images.unsplash.com/photo-1544724569-5f546fd6f2b5?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80",
        published: true
    }
];

// Current admin state
let currentAdmin = null;
let editingNewsId = null;

// Initialize news system
function initNewsSystem() {
    loadNewsOnHomepage();
    loadNewsPage();
    setupNewsEventListeners();
    checkAdminStatus();
}

// Load news on homepage
function loadNewsOnHomepage() {
    const homeNewsContainer = document.getElementById('homeNews');
    if (!homeNewsContainer) return;

    // Get featured news (limit to 3)
    const featuredNews = newsData
        .filter(item => item.published && item.featured)
        .slice(0, 3);

    if (featuredNews.length === 0) {
        homeNewsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-newspaper"></i>
                <h3>No news yet</h3>
                <p>Check back soon for updates!</p>
            </div>
        `;
        return;
    }

    homeNewsContainer.innerHTML = featuredNews.map(news => `
        <div class="news-card" onclick="showNewsDetail(${news.id})">
            ${news.image ? `<img src="${news.image}" alt="${news.title}" class="news-image">` : 
              `<div class="news-image"><i class="fas fa-newspaper"></i></div>`}
            <div class="news-content">
                <span class="news-category-badge">${news.category}</span>
                <h3 class="news-title">${news.title}</h3>
                <p class="news-excerpt">${news.excerpt}</p>
                <div class="news-meta">
                    <span class="news-date">
                        <i class="far fa-calendar"></i> ${formatDate(news.date)}
                    </span>
                    <span class="news-views">
                        <i class="far fa-eye"></i> ${news.views}
                    </span>
                </div>
            </div>
        </div>
    `).join('');
}

// Load news on news page
function loadNewsPage() {
    const newsGrid = document.getElementById('newsGrid');
    const newsPagination = document.getElementById('newsPagination');
    if (!newsGrid || !newsPagination) return;

    // Get filter values
    const category = document.querySelector('.news-category.active')?.dataset.category || 'all';
    const searchTerm = document.getElementById('newsSearch')?.value.toLowerCase() || '';
    const sortBy = document.getElementById('newsSort')?.value || 'newest';

    // Filter news
    let filteredNews = newsData.filter(item => {
        if (!item.published) return false;
        if (category !== 'all' && item.category !== category) return false;
        if (searchTerm && !item.title.toLowerCase().includes(searchTerm) && 
            !item.content.toLowerCase().includes(searchTerm) && 
            !item.tags.some(tag => tag.toLowerCase().includes(searchTerm))) {
            return false;
        }
        return true;
    });

    // Sort news
    filteredNews.sort((a, b) => {
        if (sortBy === 'newest') return new Date(b.date) - new Date(a.date);
        if (sortBy === 'oldest') return new Date(a.date) - new Date(b.date);
        if (sortBy === 'popular') return b.views - a.views;
        return 0;
    });

    // Check if admin is logged in
    const isAdmin = currentAdmin !== null;

    if (filteredNews.length === 0) {
        newsGrid.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-newspaper"></i>
                <h3>No news articles found</h3>
                <p>Try changing your search or filter criteria</p>
            </div>
        `;
        newsPagination.style.display = 'none';
        return;
    }

    // Display news
    newsGrid.innerHTML = filteredNews.map(news => `
        <div class="news-card" onclick="showNewsDetail(${news.id})">
            ${news.featured ? '<span class="featured-badge">Featured</span>' : ''}
            ${isAdmin ? `
                <div class="news-admin-actions">
                    <button class="admin-action-btn edit-btn" onclick="editNews(${news.id}); event.stopPropagation()">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="admin-action-btn delete-btn" onclick="deleteNews(${news.id}); event.stopPropagation()">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            ` : ''}
            ${news.image ? `<img src="${news.image}" alt="${news.title}" class="news-image">` : 
              `<div class="news-image"><i class="fas fa-newspaper"></i></div>`}
            <div class="news-content">
                <span class="news-category-badge">${news.category}</span>
                <h3 class="news-title">${news.title}</h3>
                <p class="news-excerpt">${news.excerpt}</p>
                <div class="news-meta">
                    <span class="news-date">
                        <i class="far fa-calendar"></i> ${formatDate(news.date)}
                    </span>
                    <span class="news-views">
                        <i class="far fa-eye"></i> ${news.views}
                    </span>
                </div>
            </div>
        </div>
    `).join('');

    // Show pagination
    newsPagination.style.display = 'flex';
}

// Show news detail
function showNewsDetail(newsId) {
    const news = newsData.find(item => item.id === newsId);
    if (!news) return;

    // Increment view count
    news.views++;

    const modal = document.getElementById('newsDetailModal');
    const content = document.getElementById('newsDetailContent');
    
    content.innerHTML = `
        <div class="news-detail">
            <div class="news-detail-header">
                <span class="news-detail-category">${news.category}</span>
                <h1 class="news-detail-title">${news.title}</h1>
                <div class="news-detail-meta">
                    <span><i class="far fa-calendar"></i> ${formatDate(news.date)}</span>
                    <span><i class="far fa-user"></i> ${news.author}</span>
                    <span><i class="far fa-eye"></i> ${news.views} views</span>
                </div>
            </div>
            
            ${news.image ? `<img src="${news.image}" alt="${news.title}" class="news-detail-image">` : ''}
            
            <div class="news-detail-content">
                ${news.content}
            </div>
            
            <div class="news-detail-footer">
                <div class="news-tags">
                    ${news.tags.map(tag => `<span class="news-tag">#${tag}</span>`).join('')}
                </div>
                <button onclick="shareNews(${news.id})" class="btn btn-outline">
                    <i class="fas fa-share-alt"></i> Share
                </button>
            </div>
        </div>
    `;
    
    showModal('newsDetailModal');
}

// Edit news
function editNews(newsId) {
    const news = newsData.find(item => item.id === newsId);
    if (!news) return;

    editingNewsId = newsId;
    
    // Fill form with news data
    document.getElementById('newsTitle').value = news.title;
    document.getElementById('newsCategory').value = news.category;
    document.getElementById('newsAuthor').value = news.author || '';
    document.getElementById('newsTags').value = news.tags.join(', ');
    document.getElementById('newsContent').innerHTML = news.content;
    document.getElementById('newsFeatured').checked = news.featured;
    document.getElementById('newsPublished').checked = news.published;
    document.getElementById('newsId').value = news.id;
    
    // Handle image preview
    const imagePreview = document.getElementById('imagePreview');
    const previewImg = document.getElementById('previewImg');
    if (news.image) {
        previewImg.src = news.image;
        imagePreview.style.display = 'block';
    } else {
        imagePreview.style.display = 'none';
    }
    
    document.getElementById('modalTitle').textContent = 'Edit News Article';
    showModal('newsModal');
}

// Add new news
function addNews() {
    editingNewsId = null;
    
    // Reset form
    document.getElementById('newsForm').reset();
    document.getElementById('newsContent').innerHTML = '';
    document.getElementById('imagePreview').style.display = 'none';
    document.getElementById('newsId').value = '';
    document.getElementById('modalTitle').textContent = 'Add News Article';
    
    showModal('newsModal');
}

// Save news (add or edit)
function saveNews(event) {
    event.preventDefault();
    
    const formData = {
        id: editingNewsId || Date.now(), // Use timestamp as ID for new articles
        title: document.getElementById('newsTitle').value,
        category: document.getElementById('newsCategory').value,
        author: document.getElementById('newsAuthor').value || 'Church Staff',
        tags: document.getElementById('newsTags').value.split(',').map(tag => tag.trim()).filter(tag => tag),
        content: document.getElementById('newsContent').innerHTML,
        excerpt: document.getElementById('newsContent').textContent.slice(0, 150) + '...',
        date: new Date().toISOString().split('T')[0],
        views: editingNewsId ? newsData.find(n => n.id === editingNewsId)?.views || 0 : 0,
        featured: document.getElementById('newsFeatured').checked,
        published: document.getElementById('newsPublished').checked,
        image: document.getElementById('previewImg').src || ''
    };
    
    if (editingNewsId) {
        // Update existing news
        const index = newsData.findIndex(item => item.id === editingNewsId);
        if (index !== -1) {
            newsData[index] = { ...newsData[index], ...formData };
        }
    } else {
        // Add new news
        newsData.unshift(formData);
    }
    
    // Save to localStorage (for persistence)
    localStorage.setItem('churchNews', JSON.stringify(newsData));
    
    // Update displays
    loadNewsOnHomepage();
    loadNewsPage();
    
    // Close modal
    closeModal('newsModal');
    
    // Show success message
    showNotification('News article saved successfully!', 'success');
}

// Delete news
function deleteNews(newsId) {
    if (confirm('Are you sure you want to delete this news article?')) {
        newsData = newsData.filter(item => item.id !== newsId);
        localStorage.setItem('churchNews', JSON.stringify(newsData));
        loadNewsOnHomepage();
        loadNewsPage();
        showNotification('News article deleted!', 'success');
    }
}

// Share news
function shareNews(newsId) {
    const news = newsData.find(item => item.id === newsId);
    if (!news) return;
    
    const url = window.location.href.split('#')[0] + `#news?article=${newsId}`;
    const text = `Check out this news from Ruach Church: ${news.title}`;
    
    if (navigator.share) {
        navigator.share({
            title: news.title,
            text: news.excerpt,
            url: url
        });
    } else {
        // Fallback: copy to clipboard
        navigator.clipboard.writeText(`${text}\n${url}`).then(() => {
            showNotification('Link copied to clipboard!', 'success');
        });
    }
}

// Setup event listeners for news
function setupNewsEventListeners() {
    // Category filter
    document.querySelectorAll('.news-category').forEach(button => {
        button.addEventListener('click', function() {
            document.querySelectorAll('.news-category').forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            loadNewsPage();
        });
    });
    
    // Search input
    const searchInput = document.getElementById('newsSearch');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(loadNewsPage, 300));
    }
    
    // Sort select
    const sortSelect = document.getElementById('newsSort');
    if (sortSelect) {
        sortSelect.addEventListener('change', loadNewsPage);
    }
    
    // Add news button
    const addNewsBtn = document.getElementById('addNewsBtn');
    if (addNewsBtn) {
        addNewsBtn.addEventListener('click', addNews);
    }
    
    // News form submission
    const newsForm = document.getElementById('newsForm');
    if (newsForm) {
        newsForm.addEventListener('submit', saveNews);
    }
    
    // Image upload
    const newsImageInput = document.getElementById('newsImage');
    if (newsImageInput) {
        newsImageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(event) {
                    const previewImg = document.getElementById('previewImg');
                    const imagePreview = document.getElementById('imagePreview');
                    previewImg.src = event.target.result;
                    imagePreview.style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Editor toolbar
    document.querySelectorAll('.format-btn').forEach(button => {
        button.addEventListener('click', function() {
            const format = this.dataset.format;
            const editor = document.getElementById('newsContent');
            
            document.execCommand(format, false, null);
            editor.focus();
        });
    });
    
    // Newsletter form
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = this.querySelector('input[type="email"]').value;
            // In a real app, send to server
            showNotification('Thank you for subscribing!', 'success');
            this.reset();
        });
    }
}

// Check admin status
function checkAdminStatus() {
    const admin = localStorage.getItem('churchAdmin');
    if (admin) {
        currentAdmin = JSON.parse(admin);
        showAdminControls();
    }
}

// Show admin controls
function showAdminControls() {
    // Show admin controls on news page
    const adminControls = document.getElementById('newsAdminControls');
    if (adminControls) {
        adminControls.style.display = 'block';
    }
    
    // Show add news button
    const addNewsBtn = document.getElementById('addNewsBtn');
    if (addNewsBtn) {
        addNewsBtn.style.display = 'block';
    }
}

// Utility functions
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
}

function showNotification(message, type = 'success') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        <span>${message}</span>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Show and auto-remove
    setTimeout(() => {
        notification.classList.add('show');
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }, 10);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Load saved news from localStorage on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load saved news from localStorage
    const savedNews = localStorage.getItem('churchNews');
    if (savedNews) {
        try {
            newsData = JSON.parse(savedNews);
        } catch (e) {
            console.error('Error loading saved news:', e);
        }
    }
    
    // Initialize news system
    initNewsSystem();
    
    // Close modal when clicking X
    document.querySelectorAll('.close-modal').forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = '';
            }
        });
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
            document.body.style.overflow = '';
        }
    });
});
// ===== ADMIN LOGIN SYSTEM =====

// Admin credentials (in a real app, this would be on a secure server)
const ADMIN_CREDENTIALS = [
    { username: 'admin', password: 'church123', role: 'admin' },
    { username: 'pastor', password: 'ruach2025', role: 'pastor' },
    { username: 'staff', password: 'staff123', role: 'staff' }
];

// Handle admin login
function handleAdminLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('adminUsername').value;
    const password = document.getElementById('adminPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    const admin = ADMIN_CREDENTIALS.find(
        cred => cred.username === username && cred.password === password
    );
    
    if (admin) {
        // Login successful
        currentAdmin = {
            username: admin.username,
            role: admin.role,
            loggedInAt: new Date().toISOString()
        };
        
        // Save to localStorage if remember me is checked
        if (rememberMe) {
            localStorage.setItem('churchAdmin', JSON.stringify(currentAdmin));
        } else {
            sessionStorage.setItem('churchAdmin', JSON.stringify(currentAdmin));
        }
        
        // Show success message
        showNotification('Login successful! Welcome, ' + admin.username, 'success');
        
        // Close login modal
        closeModal('adminLoginModal');
        
        // Show admin controls
        showAdminControls();
        
        // Show admin panel button
        document.getElementById('adminPanel').style.display = 'block';
        
        // Update UI
        const adminLoginLink = document.getElementById('adminLoginLink');
        if (adminLoginLink) {
            adminLoginLink.innerHTML = `
                <i class="fas fa-user-shield"></i> ${admin.username}
            `;
            adminLoginLink.style.color = '#2ecc71';
            adminLoginLink.onclick = function(e) {
                e.preventDefault();
                showAdminPanel();
            };
        }
        
    } else {
        // Login failed
        document.getElementById('adminLoginError').textContent = 
            'Invalid username or password';
        showNotification('Login failed. Please check your credentials.', 'error');
    }
}

// Show admin panel
function showAdminPanel() {
    document.getElementById('adminPanelModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
}

// Handle admin logout
function handleAdminLogout() {
    currentAdmin = null;
    localStorage.removeItem('churchAdmin');
    sessionStorage.removeItem('churchAdmin');
    
    // Hide admin controls
    document.getElementById('newsAdminControls').style.display = 'none';
    document.getElementById('adminPanel').style.display = 'none';
    
    // Reset admin login link
    const adminLoginLink = document.getElementById('adminLoginLink');
    if (adminLoginLink) {
        adminLoginLink.innerHTML = `
            <i class="fas fa-user-shield"></i> Admin
        `;
        adminLoginLink.style.color = '#e74c3c';
        adminLoginLink.onclick = function(e) {
            e.preventDefault();
            showModal('adminLoginModal');
        };
    }
    
    showNotification('Logged out successfully', 'success');
    closeModal('adminPanelModal');
}

// Update your DOMContentLoaded event listener to include admin login:
document.addEventListener('DOMContentLoaded', function() {
    // ... existing code ...
    
    // Admin login form
    const adminLoginForm = document.getElementById('adminLoginForm');
    if (adminLoginForm) {
        adminLoginForm.addEventListener('submit', handleAdminLogin);
    }
    
    // Admin login link
    const adminLoginLink = document.getElementById('adminLoginLink');
    if (adminLoginLink) {
        adminLoginLink.addEventListener('click', function(e) {
            e.preventDefault();
            if (currentAdmin) {
                showAdminPanel();
            } else {
                showModal('adminLoginModal');
            }
        });
    }
    
    // Admin logout button
    const adminLogoutBtn = document.getElementById('adminLogoutBtn');
    if (adminLogoutBtn) {
        adminLogoutBtn.addEventListener('click', handleAdminLogout);
    }
    
    // Close admin modal buttons
    document.querySelectorAll('.admin-close-modal, .close-modal').forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal, .admin-modal');
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = '';
            }
        });
    });
});