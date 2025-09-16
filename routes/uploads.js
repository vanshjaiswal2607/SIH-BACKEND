const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { protect } = require('../middleware/auth');

const router = express.Router();

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(uploadDir, 'complaints');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Generate unique filename with timestamp and random string
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + extension);
  }
});

// File filter to validate file types
const fileFilter = (req, file, cb) => {
  // Allowed mime types
  const allowedTypes = [
    'image/jpeg',
    'image/jpg', 
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
    'video/mp4',
    'video/avi',
    'video/mov',
    'video/wmv'
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Allowed types: images, PDF, and videos`), false);
  }
};

// Configure multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 5 // Maximum 5 files per request
  }
});

// @desc    Upload files for complaints
// @route   POST /api/uploads/complaint
// @access  Private
router.post('/complaint', protect, upload.array('files', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No files uploaded'
      });
    }

    const uploadedFiles = req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      path: file.path,
      url: `/uploads/complaints/${file.filename}`,
      uploadedAt: new Date()
    }));

    res.status(200).json({
      success: true,
      message: `${uploadedFiles.length} file(s) uploaded successfully`,
      data: uploadedFiles
    });
  } catch (error) {
    console.error('Upload error:', error);

    // Clean up uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      });
    }

    if (error instanceof multer.MulterError) {
      let errorMessage = 'File upload error';
      
      switch (error.code) {
        case 'LIMIT_FILE_SIZE':
          errorMessage = 'File too large. Maximum size is 10MB per file';
          break;
        case 'LIMIT_FILE_COUNT':
          errorMessage = 'Too many files. Maximum 5 files allowed';
          break;
        case 'LIMIT_UNEXPECTED_FILE':
          errorMessage = 'Unexpected file field';
          break;
        default:
          errorMessage = error.message;
      }

      return res.status(400).json({
        success: false,
        error: errorMessage
      });
    }

    res.status(500).json({
      success: false,
      error: error.message || 'Server error during file upload'
    });
  }
});

// @desc    Upload single file (general purpose)
// @route   POST /api/uploads/single
// @access  Private
router.post('/single', protect, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded'
      });
    }

    const uploadedFile = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      path: req.file.path,
      url: `/uploads/complaints/${req.file.filename}`,
      uploadedAt: new Date()
    };

    res.status(200).json({
      success: true,
      message: 'File uploaded successfully',
      data: uploadedFile
    });
  } catch (error) {
    console.error('Single upload error:', error);

    // Clean up uploaded file if error occurs
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    if (error instanceof multer.MulterError) {
      let errorMessage = 'File upload error';
      
      switch (error.code) {
        case 'LIMIT_FILE_SIZE':
          errorMessage = 'File too large. Maximum size is 10MB';
          break;
        default:
          errorMessage = error.message;
      }

      return res.status(400).json({
        success: false,
        error: errorMessage
      });
    }

    res.status(500).json({
      success: false,
      error: error.message || 'Server error during file upload'
    });
  }
});

// @desc    Delete uploaded file
// @route   DELETE /api/uploads/:filename
// @access  Private
router.delete('/:filename', protect, async (req, res) => {
  try {
    const { filename } = req.params;
    
    // Validate filename to prevent directory traversal
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename'
      });
    }

    const filePath = path.join(uploadDir, 'complaints', filename);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Delete file
    fs.unlinkSync(filePath);

    res.status(200).json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during file deletion'
    });
  }
});

// @desc    Get file info
// @route   GET /api/uploads/info/:filename
// @access  Private
router.get('/info/:filename', protect, async (req, res) => {
  try {
    const { filename } = req.params;
    
    // Validate filename to prevent directory traversal
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename'
      });
    }

    const filePath = path.join(uploadDir, 'complaints', filename);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Get file stats
    const stats = fs.statSync(filePath);
    const extension = path.extname(filename);

    const fileInfo = {
      filename: filename,
      extension: extension,
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      url: `/uploads/complaints/${filename}`,
      isImage: ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(extension.toLowerCase()),
      isPDF: extension.toLowerCase() === '.pdf',
      isVideo: ['.mp4', '.avi', '.mov', '.wmv'].includes(extension.toLowerCase())
    };

    res.status(200).json({
      success: true,
      data: fileInfo
    });
  } catch (error) {
    console.error('Get file info error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while getting file info'
    });
  }
});

// @desc    Upload avatar/profile picture
// @route   POST /api/uploads/avatar
// @access  Private
router.post('/avatar', protect, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No avatar file uploaded'
      });
    }

    // Only allow image files for avatars
    if (!req.file.mimetype.startsWith('image/')) {
      // Delete uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      
      return res.status(400).json({
        success: false,
        error: 'Avatar must be an image file'
      });
    }

    const uploadedFile = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      url: `/uploads/complaints/${req.file.filename}`,
      uploadedAt: new Date()
    };

    res.status(200).json({
      success: true,
      message: 'Avatar uploaded successfully',
      data: uploadedFile
    });
  } catch (error) {
    console.error('Avatar upload error:', error);

    // Clean up uploaded file if error occurs
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    if (error instanceof multer.MulterError) {
      let errorMessage = 'Avatar upload error';
      
      switch (error.code) {
        case 'LIMIT_FILE_SIZE':
          errorMessage = 'Avatar file too large. Maximum size is 10MB';
          break;
        default:
          errorMessage = error.message;
      }

      return res.status(400).json({
        success: false,
        error: errorMessage
      });
    }

    res.status(500).json({
      success: false,
      error: error.message || 'Server error during avatar upload'
    });
  }
});

// @desc    Get upload statistics
// @route   GET /api/uploads/stats
// @access  Private (Admin only)
router.get('/stats', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const complaintsDir = path.join(uploadDir, 'complaints');
    
    if (!fs.existsSync(complaintsDir)) {
      return res.status(200).json({
        success: true,
        data: {
          totalFiles: 0,
          totalSize: 0,
          imageFiles: 0,
          videoFiles: 0,
          pdfFiles: 0,
          otherFiles: 0
        }
      });
    }

    const files = fs.readdirSync(complaintsDir);
    let stats = {
      totalFiles: 0,
      totalSize: 0,
      imageFiles: 0,
      videoFiles: 0,
      pdfFiles: 0,
      otherFiles: 0
    };

    files.forEach(filename => {
      const filePath = path.join(complaintsDir, filename);
      const fileStats = fs.statSync(filePath);
      const extension = path.extname(filename).toLowerCase();

      stats.totalFiles++;
      stats.totalSize += fileStats.size;

      if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(extension)) {
        stats.imageFiles++;
      } else if (['.mp4', '.avi', '.mov', '.wmv'].includes(extension)) {
        stats.videoFiles++;
      } else if (extension === '.pdf') {
        stats.pdfFiles++;
      } else {
        stats.otherFiles++;
      }
    });

    // Convert size to readable format
    stats.totalSizeMB = (stats.totalSize / (1024 * 1024)).toFixed(2);

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Upload stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while getting upload statistics'
    });
  }
});

// @desc    Clean up old files (Admin only)
// @route   DELETE /api/uploads/cleanup
// @access  Private (Admin only)
router.delete('/cleanup', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const { olderThanDays = 30 } = req.query;
    const complaintsDir = path.join(uploadDir, 'complaints');
    
    if (!fs.existsSync(complaintsDir)) {
      return res.status(200).json({
        success: true,
        message: 'No files to clean up',
        deletedCount: 0
      });
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(olderThanDays));

    const files = fs.readdirSync(complaintsDir);
    let deletedCount = 0;

    files.forEach(filename => {
      const filePath = path.join(complaintsDir, filename);
      const fileStats = fs.statSync(filePath);

      if (fileStats.mtime < cutoffDate) {
        fs.unlinkSync(filePath);
        deletedCount++;
      }
    });

    res.status(200).json({
      success: true,
      message: `Cleaned up ${deletedCount} old files`,
      deletedCount
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during cleanup'
    });
  }
});

module.exports = router;
