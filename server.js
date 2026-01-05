// ============================================
// RUACH CHURCH BACKEND - COMPLETE SINGLE FILE
// ============================================

// Import dependencies
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// CONFIGURATION
// ============================================

// Ensure uploads directory exists
const UPLOAD_DIR = process.env.UPLOAD_PATH || './uploads';
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP'
});

// ============================================
// DATABASE MODELS
// ============================================

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['admin', 'pastor', 'staff', 'member'],
        default: 'member'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Remove password from JSON response
userSchema.methods.toJSON = function() {
    const user = this.toObject();
    delete user.password;
    return user;
};

const User = mongoose.model('User', userSchema);

// File Schema
const fileSchema = new mongoose.Schema({
    filename: {
        type: String,
        required: true
    },
    originalName: {
        type: String,
        required: true
    },
    path: {
        type: String,
        required: true
    },
    size: {
        type: Number,
        required: true
    },
    mimetype: {
        type: String,
        required: true
    },
    extension: {
        type: String
    },
    category: {
        type: String,
        enum: ['sermon', 'event', 'form', 'music', 'other'],
        default: 'other'
    },
    description: {
        type: String,
        default: ''
    },
    visibility: {
        type: String,
        enum: ['public', 'members', 'staff'],
        default: 'public'
    },
    uploadedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    downloadCount: {
        type: Number,
        default: 0
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const File = mongoose.model('File', fileSchema);

// ============================================
// MIDDLEWARE
// ============================================

// Security middleware
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
}));
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, UPLOAD_DIR)));

// Authentication middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error('No authentication token');
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded.id, isActive: true });
        
        if (!user) throw new Error('User not found');
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

const adminOnly = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'pastor') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// File upload middleware
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = (process.env.ALLOWED_FILE_TYPES || 'jpg,jpeg,png,gif,pdf,doc,docx,txt,mp3,mp4').split(',');
    const ext = path.extname(file.originalname).toLowerCase().substring(1);
    
    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error(`File type .${ext} is not allowed`), false);
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024,
        files: 10
    },
    fileFilter: fileFilter
});

// ============================================
// DATABASE CONNECTION
// ============================================

async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('✅ MongoDB Connected');
        
        // Create default admin user
        const adminExists = await User.findOne({ username: process.env.ADMIN_USERNAME });
        if (!adminExists) {
            const admin = new User({
                username: process.env.ADMIN_USERNAME,
                email: process.env.ADMIN_EMAIL,
                password: process.env.ADMIN_PASSWORD,
                role: 'admin'
            });
            await admin.save();
            console.log('✅ Default admin user created');
        }
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        console.log('💡 Make sure MongoDB is running: mongod');
        process.exit(1);
    }
}

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, role = 'member' } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ error: 'User already exists' });
        
        const user = new User({ username, email, password, role });
        await user.save();
        
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );
        
        res.status(201).json({ success: true, token, user: user.toJSON() });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const user = await User.findOne({ username, isActive: true });
        
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );
        
        res.json({ success: true, token, user: user.toJSON() });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token
app.get('/api/auth/verify', async (req, res) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ error: 'No token provided' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user || !user.isActive) return res.status(401).json({ error: 'Invalid token' });
        
        res.json({ valid: true, user });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Get current user
app.get('/api/auth/me', async (req, res) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ error: 'No token provided' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({ user });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============================================
// FILE UPLOAD ROUTES
// ============================================

// Upload files
app.post('/api/upload', authMiddleware, adminOnly, upload.array('files', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }
        
        const { category = 'other', description = '', visibility = 'public' } = req.body;
        const uploadedFiles = [];
        
        for (const file of req.files) {
            const fileDoc = new File({
                filename: file.filename,
                originalName: file.originalname,
                path: file.path,
                size: file.size,
                mimetype: file.mimetype,
                extension: file.originalname.split('.').pop().toLowerCase(),
                category,
                description,
                visibility,
                uploadedBy: req.user._id,
                downloadCount: 0
            });
            
            await fileDoc.save();
            uploadedFiles.push(fileDoc);
        }
        
        res.status(201).json({
            success: true,
            message: `${req.files.length} file(s) uploaded successfully`,
            files: uploadedFiles
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed', message: error.message });
    }
});

// ============================================
// FILE MANAGEMENT ROUTES
// ============================================

// Get all files
app.get('/api/files', async (req, res) => {
    try {
        const { category, search, page = 1, limit = 20 } = req.query;
        
        const query = { isActive: true, visibility: 'public' };
        if (category && category !== 'all') query.category = category;
        if (search) {
            query.$or = [
                { originalName: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const files = await File.find(query)
            .populate('uploadedBy', 'username')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await File.countDocuments(query);
        
        res.json({
            success: true,
            files,
            total,
            page: parseInt(page),
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get files error:', error);
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// Get file by ID
app.get('/api/files/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id).populate('uploadedBy', 'username');
        
        if (!file || !file.isActive) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        if (file.visibility !== 'public') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        res.json({ success: true, file });
    } catch (error) {
        console.error('Get file error:', error);
        res.status(500).json({ error: 'Failed to fetch file' });
    }
});

// Download file
app.get('/api/files/download/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        
        if (!file || !file.isActive) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        if (!fs.existsSync(file.path)) {
            return res.status(404).json({ error: 'File not found on server' });
        }
        
        file.downloadCount += 1;
        await file.save();
        
        res.download(file.path, file.originalName);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// ============================================
// UTILITY ROUTES
// ============================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        service: 'Ruach Church Backend',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Welcome route
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to Ruach Marshallese Full Gospel Church API',
        endpoints: {
            auth: '/api/auth',
            upload: '/api/upload',
            files: '/api/files',
            health: '/api/health'
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error'
    });
});

// ============================================
// START SERVER
// ============================================

async function startServer() {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`
╔══════════════════════════════════════════════════════════╗
║   🏛️  Ruach Church Backend Server                       ║
║   🚀  Running on port ${PORT}                           ║
║   📁  Uploads: ${path.join(__dirname, UPLOAD_DIR)}      ║
║   🔗  Health: http://localhost:${PORT}/api/health       ║
║   📄  API Docs: http://localhost:${PORT}/               ║
╚══════════════════════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
// ============================================
// NEWS MANAGEMENT ROUTES
// ============================================

// News Schema
const newsSchema = new mongoose.Schema({
  title: {
      type: String,
      required: true,
      trim: true
  },
  slug: {
      type: String,
      unique: true,
      lowercase: true
  },
  excerpt: {
      type: String,
      trim: true
  },
  content: {
      type: String,
      required: true
  },
  category: {
      type: String,
      enum: ['announcements', 'events', 'ministries', 'testimonies', 'general'],
      default: 'general'
  },
  image: {
      type: String
  },
  author: {
      type: String,
      default: 'Church Admin'
  },
  tags: [{
      type: String,
      trim: true
  }],
  featured: {
      type: Boolean,
      default: false
  },
  published: {
      type: Boolean,
      default: true
  },
  views: {
      type: Number,
      default: 0
  },
  createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
  },
  createdAt: {
      type: Date,
      default: Date.now
  },
  updatedAt: {
      type: Date,
      default: Date.now
  }
});

// Generate slug before saving
newsSchema.pre('save', function(next) {
  if (this.isModified('title')) {
      this.slug = this.title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '');
  }
  next();
});

const News = mongoose.model('News', newsSchema);

// Get all news (public)
app.get('/api/news', async (req, res) => {
  try {
      const { 
          page = 1, 
          limit = 6, 
          category = '', 
          search = '', 
          sort = 'newest' 
      } = req.query;
      
      const skip = (parseInt(page) - 1) * parseInt(limit);
      
      // Build query
      const query = { published: true };
      
      if (category) {
          query.category = category;
      }
      
      if (search) {
          query.$or = [
              { title: { $regex: search, $options: 'i' } },
              { content: { $regex: search, $options: 'i' } },
              { excerpt: { $regex: search, $options: 'i' } },
              { tags: { $regex: search, $options: 'i' } }
          ];
      }
      
      // Build sort
      let sortOption = { createdAt: -1 };
      if (sort === 'oldest') sortOption = { createdAt: 1 };
      if (sort === 'popular') sortOption = { views: -1 };
      
      // Get articles
      const articles = await News.find(query)
          .select('-__v')
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit));
      
      // Get total count
      const total = await News.countDocuments(query);
      
      res.json({
          success: true,
          articles,
          total,
          page: parseInt(page),
          totalPages: Math.ceil(total / limit)
      });
      
  } catch (error) {
      console.error('Get news error:', error);
      res.status(500).json({ error: 'Failed to fetch news' });
  }
});

// Get single news article
app.get('/api/news/:id', async (req, res) => {
  try {
      const article = await News.findById(req.params.id);
      
      if (!article) {
          return res.status(404).json({ error: 'Article not found' });
      }
      
      res.json({
          success: true,
          article
      });
      
  } catch (error) {
      console.error('Get article error:', error);
      res.status(500).json({ error: 'Failed to fetch article' });
  }
});

// Increment view count
app.post('/api/news/:id/view', async (req, res) => {
  try {
      await News.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
      res.json({ success: true });
  } catch (error) {
      res.json({ success: false });
  }
});

// Create news article (admin only)
app.post('/api/news', authMiddleware, adminOnly, upload.single('image'), async (req, res) => {
  try {
      const { 
          title, 
          content, 
          category, 
          author, 
          tags, 
          featured, 
          published,
          excerpt 
      } = req.body;
      
      if (!title || !content) {
          return res.status(400).json({ error: 'Title and content are required' });
      }
      
      const tagArray = tags ? tags.split(',').map(tag => tag.trim()) : [];
      
      const articleData = {
          title,
          content,
          category: category || 'general',
          author: author || 'Church Admin',
          tags: tagArray,
          featured: featured === 'true',
          published: published === 'true',
          excerpt: excerpt || content.substring(0, 200) + '...',
          createdBy: req.user._id
      };
      
      if (req.file) {
          articleData.image = req.file.filename;
      }
      
      const article = new News(articleData);
      await article.save();
      
      res.status(201).json({
          success: true,
          message: 'Article created successfully',
          article
      });
      
  } catch (error) {
      console.error('Create article error:', error);
      res.status(500).json({ error: 'Failed to create article' });
  }
});

// Update news article (admin only)
app.put('/api/news/:id', authMiddleware, adminOnly, upload.single('image'), async (req, res) => {
  try {
      const { 
          title, 
          content, 
          category, 
          author, 
          tags, 
          featured, 
          published,
          excerpt 
      } = req.body;
      
      const updates = {
          title,
          content,
          category,
          author,
          tags: tags ? tags.split(',').map(tag => tag.trim()) : undefined,
          featured: featured === 'true',
          published: published === 'true',
          excerpt,
          updatedAt: new Date()
      };
      
      // Remove undefined values
      Object.keys(updates).forEach(key => updates[key] === undefined && delete updates[key]);
      
      if (req.file) {
          updates.image = req.file.filename;
          
          // Delete old image if exists
          const oldArticle = await News.findById(req.params.id);
          if (oldArticle && oldArticle.image) {
              const oldPath = path.join(UPLOAD_DIR, oldArticle.image);
              if (fs.existsSync(oldPath)) {
                  fs.unlinkSync(oldPath);
              }
          }
      }
      
      const article = await News.findByIdAndUpdate(
          req.params.id,
          updates,
          { new: true, runValidators: true }
      );
      
      if (!article) {
          return res.status(404).json({ error: 'Article not found' });
      }
      
      res.json({
          success: true,
          message: 'Article updated successfully',
          article
      });
      
  } catch (error) {
      console.error('Update article error:', error);
      res.status(500).json({ error: 'Failed to update article' });
  }
});

// Delete news article (admin only)
app.delete('/api/news/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
      const article = await News.findById(req.params.id);
      
      if (!article) {
          return res.status(404).json({ error: 'Article not found' });
      }
      
      // Delete image if exists
      if (article.image) {
          const imagePath = path.join(UPLOAD_DIR, article.image);
          if (fs.existsSync(imagePath)) {
              fs.unlinkSync(imagePath);
          }
      }
      
      await News.findByIdAndDelete(req.params.id);
      
      res.json({
          success: true,
          message: 'Article deleted successfully'
      });
      
  } catch (error) {
      console.error('Delete article error:', error);
      res.status(500).json({ error: 'Failed to delete article' });
  }
});

// Newsletter subscription
app.post('/api/newsletter/subscribe', async (req, res) => {
  try {
      const { email } = req.body;
      
      if (!email) {
          return res.status(400).json({ error: 'Email is required' });
      }
      
      // Here you would save to database and send confirmation email
      // For now, just acknowledge
      
      console.log('Newsletter subscription:', email);
      
      res.json({
          success: true,
          message: 'Thank you for subscribing!'
      });
      
  } catch (error) {
      console.error('Newsletter subscription error:', error);
      res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// Get featured news (for homepage)
app.get('/api/news/featured', async (req, res) => {
  try {
      const featured = await News.find({ 
          published: true, 
          featured: true 
      })
      .sort({ createdAt: -1 })
      .limit(3);
      
      res.json({
          success: true,
          articles: featured
      });
      
  } catch (error) {
      console.error('Get featured news error:', error);
      res.status(500).json({ error: 'Failed to get featured news' });
  }
});

// Get recent news
app.get('/api/news/recent', async (req, res) => {
  try {
      const recent = await News.find({ published: true })
          .sort({ createdAt: -1 })
          .limit(5);
      
      res.json({
          success: true,
          articles: recent
      });
      
  } catch (error) {
      console.error('Get recent news error:', error);
      res.status(500).json({ error: 'Failed to get recent news' });
  }
});

