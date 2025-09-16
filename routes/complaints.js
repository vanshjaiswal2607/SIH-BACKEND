const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Complaint = require('../models/Complaint');
const User = require('../models/User');
const { protect, authorize, checkOwnership, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// @desc    Create new complaint
// @route   POST /api/complaints
// @access  Private/Public (with optional auth)
router.post('/', [
  body('subject')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Subject must be between 5 and 200 characters'),
  body('description')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Description must be between 10 and 2000 characters'),
  body('type')
    .isIn(['Water Supply', 'Electricity', 'Roads', 'Sanitation', 'Public Health', 'Other'])
    .withMessage('Please select a valid complaint type'),
  body('location.address')
    .trim()
    .isLength({ min: 5 })
    .withMessage('Address is required and must be at least 5 characters'),
  body('location.pincode')
    .optional()
    .matches(/^\d{6}$/)
    .withMessage('Please provide a valid 6-digit pincode')
], optionalAuth, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const {
      subject,
      description,
      type,
      location,
      category,
      priority,
      tags,
      isAnonymous,
      citizenInfo
    } = req.body;

    let userId = null;

    // Handle anonymous complaints or when user is not logged in
    if (!req.user && !isAnonymous && !citizenInfo) {
      return res.status(400).json({
        success: false,
        error: 'Please login or provide citizen information for non-anonymous complaints'
      });
    }

    // If user is logged in, use their ID
    if (req.user) {
      userId = req.user._id;
    } else if (citizenInfo && !isAnonymous) {
      // For non-logged-in users, create or find user based on citizenInfo
      const { name, email, phone } = citizenInfo;
      
      if (!name || !email || !phone) {
        return res.status(400).json({
          success: false,
          error: 'Name, email, and phone are required for citizen information'
        });
      }

      // Check if user exists
      let user = await User.findOne({
        $or: [{ email }, { phone }]
      });

      if (!user) {
        // Create new user
        user = await User.create({
          name,
          email,
          phone,
          role: 'citizen',
          isVerified: false
        });
      }

      userId = user._id;
    }

    // Create complaint
    const complaintData = {
      subject,
      description,
      type,
      location,
      category: category || 'normal',
      priority: priority || 'medium',
      tags: tags || [],
      isAnonymous: isAnonymous || false,
      metadata: {
        source: 'web',
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip
      }
    };

    // Only add user if not anonymous
    if (userId && !isAnonymous) {
      complaintData.user = userId;
    }

    const complaint = await Complaint.create(complaintData);

    // Populate user data if available
    await complaint.populate([
      {
        path: 'user',
        select: 'name email phone'
      }
    ]);

    res.status(201).json({
      success: true,
      data: complaint,
      message: `Complaint registered successfully with ID: ${complaint.complaintId}`
    });
  } catch (error) {
    console.error('Create complaint error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during complaint registration'
    });
  }
});

// @desc    Get all complaints with filtering and pagination
// @route   GET /api/complaints
// @access  Public (limited) / Private (full access)
router.get('/', [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('status')
    .optional()
    .isIn(['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened'])
    .withMessage('Invalid status filter'),
  query('type')
    .optional()
    .isIn(['Water Supply', 'Electricity', 'Roads', 'Sanitation', 'Public Health', 'Other'])
    .withMessage('Invalid type filter'),
  query('department')
    .optional()
    .isIn(['water', 'electricity', 'roads', 'sanitation', 'health', 'general'])
    .withMessage('Invalid department filter')
], optionalAuth, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build filter object
    const filters = { isActive: true };

    // Add filters based on query parameters
    if (req.query.status) filters.status = req.query.status;
    if (req.query.type) filters.type = req.query.type;
    if (req.query.department) filters.department = req.query.department;
    if (req.query.priority) filters.priority = req.query.priority;
    if (req.query.category) filters.category = req.query.category;
    if (req.query.pincode) filters['location.pincode'] = req.query.pincode;

    // Text search
    if (req.query.search) {
      filters.$text = { $search: req.query.search };
    }

    // Date range filters
    if (req.query.fromDate || req.query.toDate) {
      filters.createdAt = {};
      if (req.query.fromDate) {
        filters.createdAt.$gte = new Date(req.query.fromDate);
      }
      if (req.query.toDate) {
        filters.createdAt.$lte = new Date(req.query.toDate);
      }
    }

    // If not authenticated or not admin/officer, only show public complaints
    if (!req.user || req.user.role === 'citizen') {
      // Citizens can only see their own complaints plus public non-anonymous ones
      if (req.user) {
        filters.$or = [
          { user: req.user._id },
          { isAnonymous: false }
        ];
      } else {
        filters.isAnonymous = false;
      }
    }

    // Sort options
    let sortBy = { createdAt: -1 }; // Default: newest first
    if (req.query.sortBy) {
      const allowedSorts = {
        'createdAt': { createdAt: -1 },
        'updatedAt': { updatedAt: -1 },
        'priority': { priority: -1, createdAt: -1 },
        'status': { status: 1, createdAt: -1 }
      };
      sortBy = allowedSorts[req.query.sortBy] || sortBy;
    }

    // Execute query
    const complaints = await Complaint.find(filters)
      .populate({
        path: 'user',
        select: 'name email phone'
      })
      .populate({
        path: 'assignedTo',
        select: 'name email role department'
      })
      .select(req.user && ['admin', 'officer'].includes(req.user.role) 
        ? '' // Admin/officer can see all fields
        : '-comments -statusHistory -metadata' // Limited fields for others
      )
      .sort(sortBy)
      .skip(skip)
      .limit(limit);

    // Get total count for pagination
    const total = await Complaint.countDocuments(filters);

    res.status(200).json({
      success: true,
      count: complaints.length,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
      data: complaints
    });
  } catch (error) {
    console.error('Get complaints error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching complaints'
    });
  }
});

// @desc    Get single complaint by ID or complaint ID
// @route   GET /api/complaints/:id
// @access  Public (limited) / Private
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Try to find by MongoDB _id first, then by complaintId
    let complaint = await Complaint.findById(id);
    if (!complaint) {
      complaint = await Complaint.findOne({ complaintId: id.toUpperCase() });
    }

    if (!complaint || !complaint.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Complaint not found'
      });
    }

    // Check permissions
    const isOwner = req.user && complaint.user && complaint.user.toString() === req.user._id.toString();
    const isAdmin = req.user && ['admin', 'officer'].includes(req.user.role);
    const isPublic = !complaint.isAnonymous;

    if (!isOwner && !isAdmin && !isPublic) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to view this complaint'
      });
    }

    // Populate related data
    await complaint.populate([
      {
        path: 'user',
        select: 'name email phone'
      },
      {
        path: 'assignedTo',
        select: 'name email role department'
      },
      {
        path: 'statusHistory.changedBy',
        select: 'name role'
      },
      {
        path: 'comments.user',
        select: 'name role'
      }
    ]);

    // Filter sensitive data based on user role
    let responseData = complaint.toObject();
    
    if (!isAdmin && !isOwner) {
      // Remove sensitive fields for public viewing
      delete responseData.metadata;
      responseData.comments = responseData.comments.filter(comment => comment.isPublic);
    }

    res.status(200).json({
      success: true,
      data: responseData
    });
  } catch (error) {
    console.error('Get single complaint error:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({
        success: false,
        error: 'Complaint not found'
      });
    }
    res.status(500).json({
      success: false,
      error: 'Server error while fetching complaint'
    });
  }
});

// @desc    Update complaint (only for owners and admins)
// @route   PUT /api/complaints/:id
// @access  Private
router.put('/:id', [
  body('subject')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Subject must be between 5 and 200 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Description must be between 10 and 2000 characters'),
  body('type')
    .optional()
    .isIn(['Water Supply', 'Electricity', 'Roads', 'Sanitation', 'Public Health', 'Other'])
    .withMessage('Please select a valid complaint type')
], protect, checkOwnership(Complaint), async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const complaint = req.resource;

    // Only allow updates if complaint is not resolved or closed
    if (['resolved', 'closed'].includes(complaint.status) && req.user.role !== 'admin') {
      return res.status(400).json({
        success: false,
        error: 'Cannot update resolved or closed complaints'
      });
    }

    const allowedUpdates = ['subject', 'description', 'type', 'location', 'category', 'priority', 'tags'];
    const updates = {};

    // Only include allowed fields
    Object.keys(req.body).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updates[key] = req.body[key];
      }
    });

    // Update complaint
    const updatedComplaint = await Complaint.findByIdAndUpdate(
      complaint._id,
      updates,
      {
        new: true,
        runValidators: true
      }
    ).populate([
      {
        path: 'user',
        select: 'name email phone'
      },
      {
        path: 'assignedTo',
        select: 'name email role department'
      }
    ]);

    res.status(200).json({
      success: true,
      data: updatedComplaint,
      message: 'Complaint updated successfully'
    });
  } catch (error) {
    console.error('Update complaint error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during complaint update'
    });
  }
});

// @desc    Delete complaint (soft delete)
// @route   DELETE /api/complaints/:id
// @access  Private (Owner/Admin only)
router.delete('/:id', protect, checkOwnership(Complaint), async (req, res) => {
  try {
    const complaint = req.resource;

    // Only admins can permanently delete, others get soft delete
    if (req.user.role === 'admin') {
      await Complaint.findByIdAndDelete(complaint._id);
    } else {
      complaint.isActive = false;
      await complaint.save();
    }

    res.status(200).json({
      success: true,
      message: 'Complaint deleted successfully'
    });
  } catch (error) {
    console.error('Delete complaint error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during complaint deletion'
    });
  }
});

// @desc    Update complaint status (Admin/Officer only)
// @route   PATCH /api/complaints/:id/status
// @access  Private (Admin/Officer)
router.patch('/:id/status', [
  body('status')
    .isIn(['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened'])
    .withMessage('Please provide a valid status'),
  body('comment')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Comment cannot exceed 1000 characters')
], protect, authorize('admin', 'officer'), async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { id } = req.params;
    const { status, comment } = req.body;

    const complaint = await Complaint.findById(id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'Complaint not found'
      });
    }

    // Update status using the model method
    await complaint.updateStatus(status, req.user._id, comment);

    // Populate and return updated complaint
    await complaint.populate([
      {
        path: 'user',
        select: 'name email phone'
      },
      {
        path: 'assignedTo',
        select: 'name email role department'
      },
      {
        path: 'statusHistory.changedBy',
        select: 'name role'
      }
    ]);

    res.status(200).json({
      success: true,
      data: complaint,
      message: `Complaint status updated to ${status}`
    });
  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during status update'
    });
  }
});

// @desc    Add comment to complaint
// @route   POST /api/complaints/:id/comments
// @access  Private
router.post('/:id/comments', [
  body('message')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Comment must be between 1 and 1000 characters'),
  body('isPublic')
    .optional()
    .isBoolean()
    .withMessage('isPublic must be a boolean')
], protect, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { id } = req.params;
    const { message, isPublic } = req.body;

    const complaint = await Complaint.findById(id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'Complaint not found'
      });
    }

    // Check if user can comment (owner, assigned officer, or admin)
    const isOwner = complaint.user && complaint.user.toString() === req.user._id.toString();
    const isAssigned = complaint.assignedTo && complaint.assignedTo.toString() === req.user._id.toString();
    const isAdmin = ['admin', 'officer'].includes(req.user.role);

    if (!isOwner && !isAssigned && !isAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to comment on this complaint'
      });
    }

    // Add comment
    const publicComment = isPublic !== undefined ? isPublic : true;
    await complaint.addComment(req.user._id, message, publicComment);

    // Return updated complaint with populated comments
    await complaint.populate([
      {
        path: 'comments.user',
        select: 'name role'
      }
    ]);

    res.status(201).json({
      success: true,
      data: complaint,
      message: 'Comment added successfully'
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while adding comment'
    });
  }
});

// @desc    Assign complaint to officer
// @route   PATCH /api/complaints/:id/assign
// @access  Private (Admin only)
router.patch('/:id/assign', [
  body('officerId')
    .isMongoId()
    .withMessage('Please provide a valid officer ID')
], protect, authorize('admin'), async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { id } = req.params;
    const { officerId } = req.body;

    // Check if complaint exists
    const complaint = await Complaint.findById(id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'Complaint not found'
      });
    }

    // Check if officer exists and has appropriate department
    const officer = await User.findById(officerId);
    if (!officer || officer.role !== 'officer') {
      return res.status(400).json({
        success: false,
        error: 'Invalid officer ID'
      });
    }

    // Check if officer's department matches complaint department
    if (officer.department !== complaint.department && officer.department !== 'general') {
      return res.status(400).json({
        success: false,
        error: 'Officer department does not match complaint department'
      });
    }

    // Assign complaint
    complaint.assignedTo = officerId;
    if (complaint.status === 'registered') {
      complaint.status = 'acknowledged';
      complaint.statusHistory.push({
        status: 'acknowledged',
        changedBy: req.user._id,
        comment: `Complaint assigned to ${officer.name}`,
        timestamp: new Date()
      });
    }

    await complaint.save();

    // Populate and return
    await complaint.populate([
      {
        path: 'assignedTo',
        select: 'name email role department'
      },
      {
        path: 'user',
        select: 'name email phone'
      }
    ]);

    res.status(200).json({
      success: true,
      data: complaint,
      message: `Complaint assigned to ${officer.name}`
    });
  } catch (error) {
    console.error('Assign complaint error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during complaint assignment'
    });
  }
});

// @desc    Rate complaint (after resolution)
// @route   POST /api/complaints/:id/rate
// @access  Private (Owner only)
router.post('/:id/rate', [
  body('score')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating score must be between 1 and 5'),
  body('feedback')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Feedback cannot exceed 500 characters')
], protect, checkOwnership(Complaint), async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const complaint = req.resource;
    const { score, feedback } = req.body;

    // Check if complaint is resolved
    if (complaint.status !== 'resolved') {
      return res.status(400).json({
        success: false,
        error: 'Can only rate resolved complaints'
      });
    }

    // Check if already rated
    if (complaint.rating && complaint.rating.score) {
      return res.status(400).json({
        success: false,
        error: 'Complaint has already been rated'
      });
    }

    // Add rating
    await complaint.addRating(score, feedback || '');

    res.status(200).json({
      success: true,
      data: complaint,
      message: 'Thank you for your feedback!'
    });
  } catch (error) {
    console.error('Rate complaint error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while rating complaint'
    });
  }
});

// @desc    Get complaint statistics
// @route   GET /api/complaints/stats/overview
// @access  Private (Admin/Officer)
router.get('/stats/overview', protect, authorize('admin', 'officer'), async (req, res) => {
  try {
    const filters = {};
    
    // Add department filter for officers
    if (req.user.role === 'officer' && req.user.department !== 'general') {
      filters.department = req.user.department;
    }

    // Date range filter
    if (req.query.fromDate || req.query.toDate) {
      filters.createdAt = {};
      if (req.query.fromDate) {
        filters.createdAt.$gte = new Date(req.query.fromDate);
      }
      if (req.query.toDate) {
        filters.createdAt.$lte = new Date(req.query.toDate);
      }
    }

    const stats = await Complaint.getStatistics(filters);
    const departmentStats = await Complaint.getDepartmentStats(filters);

    res.status(200).json({
      success: true,
      data: {
        overview: stats,
        departmentwise: departmentStats
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching statistics'
    });
  }
});

module.exports = router;
