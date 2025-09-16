const express = require('express');
const { query, validationResult } = require('express-validator');
const User = require('../models/User');
const Complaint = require('../models/Complaint');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

// @desc    Get user profile by ID (Admin/Officer) or self
// @route   GET /api/users/:id
// @access  Private
router.get('/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;

    // Users can only view their own profile unless they are admin/officer
    if (req.user._id.toString() !== id && !['admin', 'officer'].includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to view this profile'
      });
    }

    const user = await User.findById(id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Get user's complaint statistics
    const complaintStats = await Complaint.aggregate([
      { $match: { user: user._id, isActive: true } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          registered: { $sum: { $cond: [{ $eq: ['$status', 'registered'] }, 1, 0] } },
          acknowledged: { $sum: { $cond: [{ $eq: ['$status', 'acknowledged'] }, 1, 0] } },
          inProgress: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
          resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
          closed: { $sum: { $cond: [{ $eq: ['$status', 'closed'] }, 1, 0] } }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      data: {
        ...user.toObject(),
        complaintStats: complaintStats[0] || {
          total: 0, registered: 0, acknowledged: 0, 
          inProgress: 0, resolved: 0, closed: 0
        }
      }
    });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching user profile'
    });
  }
});

// @desc    Get user's complaints
// @route   GET /api/users/:id/complaints
// @access  Private
router.get('/:id/complaints', [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50'),
  query('status')
    .optional()
    .isIn(['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened'])
    .withMessage('Invalid status filter')
], protect, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { id } = req.params;

    // Users can only view their own complaints unless they are admin/officer
    if (req.user._id.toString() !== id && !['admin', 'officer'].includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to view these complaints'
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build filters
    const filters = { 
      user: id, 
      isActive: true 
    };
    
    if (req.query.status) filters.status = req.query.status;
    if (req.query.type) filters.type = req.query.type;
    
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

    // Text search
    if (req.query.search) {
      filters.$text = { $search: req.query.search };
    }

    const complaints = await Complaint.find(filters)
      .populate('assignedTo', 'name email department')
      .select('complaintId subject description type status priority location createdAt updatedAt rating')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

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
    console.error('Get user complaints error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching complaints'
    });
  }
});

// @desc    Get officers by department
// @route   GET /api/users/officers/:department
// @access  Private (Admin only)
router.get('/officers/:department', protect, authorize('admin'), async (req, res) => {
  try {
    const { department } = req.params;
    
    const validDepartments = ['water', 'electricity', 'roads', 'sanitation', 'health', 'general'];
    if (!validDepartments.includes(department)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid department'
      });
    }

    const officers = await User.find({
      role: 'officer',
      department,
      isActive: true
    }).select('name email phone department isVerified lastLogin');

    res.status(200).json({
      success: true,
      count: officers.length,
      data: officers
    });
  } catch (error) {
    console.error('Get officers error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching officers'
    });
  }
});

// @desc    Get all officers (for assignment purposes)
// @route   GET /api/users/officers
// @access  Private (Admin only)
router.get('/officers', protect, authorize('admin'), async (req, res) => {
  try {
    const officers = await User.find({
      role: 'officer',
      isActive: true
    })
    .select('name email phone department isVerified lastLogin')
    .sort({ name: 1 });

    res.status(200).json({
      success: true,
      count: officers.length,
      data: officers
    });
  } catch (error) {
    console.error('Get all officers error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching officers'
    });
  }
});

// @desc    Get officer's assigned complaints
// @route   GET /api/users/officer/complaints
// @access  Private (Officer only)
router.get('/officer/complaints', [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50'),
  query('status')
    .optional()
    .isIn(['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened'])
    .withMessage('Invalid status filter')
], protect, authorize('officer'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 15;
    const skip = (page - 1) * limit;

    // Build filters - show complaints assigned to this officer or unassigned ones in their department
    const filters = {
      isActive: true,
      $or: [
        { assignedTo: req.user._id },
        { 
          department: req.user.department,
          assignedTo: null
        }
      ]
    };
    
    if (req.query.status) filters.status = req.query.status;
    if (req.query.priority) filters.priority = req.query.priority;
    
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

    // Text search
    if (req.query.search) {
      filters.$text = { $search: req.query.search };
    }

    const complaints = await Complaint.find(filters)
      .populate('user', 'name email phone')
      .populate('assignedTo', 'name email')
      .sort({ 
        priority: -1,  // High priority first
        createdAt: -1  // Then newest first
      })
      .skip(skip)
      .limit(limit);

    const total = await Complaint.countDocuments(filters);

    // Get statistics for the officer
    const stats = await Complaint.aggregate([
      { 
        $match: { 
          assignedTo: req.user._id,
          isActive: true
        } 
      },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          pending: { $sum: { $cond: [{ $ne: ['$status', 'resolved'] }, 1, 0] } },
          resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
          inProgress: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      count: complaints.length,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
      stats: stats[0] || { total: 0, pending: 0, resolved: 0, inProgress: 0 },
      data: complaints
    });
  } catch (error) {
    console.error('Get officer complaints error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching assigned complaints'
    });
  }
});

// @desc    Get user activity log
// @route   GET /api/users/:id/activity
// @access  Private (Admin only or own profile)
router.get('/:id/activity', [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
], protect, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { id } = req.params;

    // Users can only view their own activity unless they are admin
    if (req.user._id.toString() !== id && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to view this activity'
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    // Get complaint activities for this user
    const activities = [];

    // Recent complaints filed
    const recentComplaints = await Complaint.find({
      user: id,
      isActive: true
    })
    .select('complaintId subject status createdAt')
    .sort({ createdAt: -1 })
    .limit(5);

    recentComplaints.forEach(complaint => {
      activities.push({
        type: 'complaint_filed',
        description: `Filed complaint: ${complaint.subject}`,
        complaintId: complaint.complaintId,
        timestamp: complaint.createdAt
      });
    });

    // Recent status changes (if officer/admin)
    if (['officer', 'admin'].includes(req.user.role)) {
      const statusChanges = await Complaint.find({
        'statusHistory.changedBy': id,
        isActive: true
      })
      .populate('statusHistory.changedBy', 'name')
      .select('complaintId statusHistory')
      .sort({ updatedAt: -1 })
      .limit(10);

      statusChanges.forEach(complaint => {
        const userChanges = complaint.statusHistory
          .filter(history => history.changedBy && history.changedBy._id.toString() === id)
          .slice(0, 3);
        
        userChanges.forEach(change => {
          activities.push({
            type: 'status_changed',
            description: `Changed complaint ${complaint.complaintId} status to ${change.status}`,
            complaintId: complaint.complaintId,
            timestamp: change.timestamp
          });
        });
      });
    }

    // Sort activities by timestamp
    activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Paginate activities
    const paginatedActivities = activities.slice(skip, skip + limit);
    const total = activities.length;

    res.status(200).json({
      success: true,
      count: paginatedActivities.length,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
      data: paginatedActivities
    });
  } catch (error) {
    console.error('Get user activity error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching user activity'
    });
  }
});

// @desc    Search users (Admin only)
// @route   GET /api/users/search
// @access  Private (Admin only)
router.get('/search', [
  query('q')
    .optional()
    .isLength({ min: 2 })
    .withMessage('Search query must be at least 2 characters'),
  query('role')
    .optional()
    .isIn(['citizen', 'officer', 'admin'])
    .withMessage('Invalid role filter')
], protect, authorize('admin'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { q, role, department } = req.query;
    const limit = parseInt(req.query.limit) || 20;

    // Build search filters
    const filters = { isActive: true };
    
    if (role) filters.role = role;
    if (department) filters.department = department;

    if (q) {
      const searchRegex = new RegExp(q, 'i');
      filters.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { phone: searchRegex }
      ];
    }

    const users = await User.find(filters)
      .select('name email phone role department isVerified createdAt lastLogin')
      .sort({ name: 1 })
      .limit(limit);

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during user search'
    });
  }
});

module.exports = router;
