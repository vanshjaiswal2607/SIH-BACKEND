const express = require('express');
const { body, query, validationResult } = require('express-validator');
const User = require('../models/User');
const Complaint = require('../models/Complaint');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

// Apply admin authentication to all routes
router.use(protect);
router.use(authorize('admin'));

// @desc    Get dashboard statistics
// @route   GET /api/admin/dashboard
// @access  Private (Admin only)
router.get('/dashboard', async (req, res) => {
  try {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfWeek = new Date(now.setDate(now.getDate() - now.getDay()));
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    // Overall statistics
    const totalComplaints = await Complaint.countDocuments({ isActive: true });
    const totalUsers = await User.countDocuments({ isActive: true, role: 'citizen' });
    const totalOfficers = await User.countDocuments({ isActive: true, role: 'officer' });
    
    // Status distribution
    const statusStats = await Complaint.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Department-wise statistics
    const departmentStats = await Complaint.getDepartmentStats({ isActive: true });

    // Recent activity (this month)
    const monthlyComplaints = await Complaint.countDocuments({
      isActive: true,
      createdAt: { $gte: startOfMonth }
    });

    const weeklyComplaints = await Complaint.countDocuments({
      isActive: true,
      createdAt: { $gte: startOfWeek }
    });

    const dailyComplaints = await Complaint.countDocuments({
      isActive: true,
      createdAt: { $gte: startOfDay }
    });

    // Performance metrics
    const resolvedThisMonth = await Complaint.countDocuments({
      isActive: true,
      status: 'resolved',
      actualResolutionDate: { $gte: startOfMonth }
    });

    // Average resolution time (in days)
    const avgResolutionTime = await Complaint.aggregate([
      {
        $match: {
          isActive: true,
          status: 'resolved',
          actualResolutionDate: { $ne: null }
        }
      },
      {
        $group: {
          _id: null,
          avgTime: {
            $avg: {
              $divide: [
                { $subtract: ['$actualResolutionDate', '$createdAt'] },
                1000 * 60 * 60 * 24 // Convert to days
              ]
            }
          }
        }
      }
    ]);

    // Top complaint types
    const topComplaintTypes = await Complaint.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Recent complaints
    const recentComplaints = await Complaint.find({ isActive: true })
      .populate('user', 'name email')
      .populate('assignedTo', 'name')
      .sort({ createdAt: -1 })
      .limit(10)
      .select('complaintId subject status type priority createdAt location.address');

    res.status(200).json({
      success: true,
      data: {
        overview: {
          totalComplaints,
          totalUsers,
          totalOfficers,
          monthlyComplaints,
          weeklyComplaints,
          dailyComplaints,
          resolvedThisMonth,
          avgResolutionTime: avgResolutionTime[0]?.avgTime?.toFixed(1) || 0
        },
        statusDistribution: statusStats,
        departmentStats,
        topComplaintTypes,
        recentComplaints
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching dashboard data'
    });
  }
});

// @desc    Get all users with filters
// @route   GET /api/admin/users
// @access  Private (Admin only)
router.get('/users', [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('role')
    .optional()
    .isIn(['citizen', 'officer', 'admin'])
    .withMessage('Invalid role filter')
], async (req, res) => {
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
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    // Build filters
    const filters = {};
    if (req.query.role) filters.role = req.query.role;
    if (req.query.isActive !== undefined) filters.isActive = req.query.isActive === 'true';
    if (req.query.isVerified !== undefined) filters.isVerified = req.query.isVerified === 'true';
    if (req.query.department) filters.department = req.query.department;

    // Text search
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      filters.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { phone: searchRegex }
      ];
    }

    const users = await User.find(filters)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments(filters);

    res.status(200).json({
      success: true,
      count: users.length,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
      data: users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching users'
    });
  }
});

// @desc    Create new officer
// @route   POST /api/admin/officers
// @access  Private (Admin only)
router.post('/officers', [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('phone')
    .matches(/^[6-9]\d{9}$/)
    .withMessage('Please provide a valid Indian phone number'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('department')
    .isIn(['water', 'electricity', 'roads', 'sanitation', 'health', 'general'])
    .withMessage('Please select a valid department')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { name, email, phone, password, department, address } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User with this email or phone already exists'
      });
    }

    // Create officer
    const officer = await User.create({
      name,
      email,
      phone,
      password,
      role: 'officer',
      department,
      address: address || {},
      isVerified: true,
      isActive: true
    });

    // Remove password from response
    officer.password = undefined;

    res.status(201).json({
      success: true,
      data: officer,
      message: 'Officer created successfully'
    });
  } catch (error) {
    console.error('Create officer error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during officer creation'
    });
  }
});

// @desc    Update user status (activate/deactivate)
// @route   PATCH /api/admin/users/:id/status
// @access  Private (Admin only)
router.patch('/users/:id/status', [
  body('isActive')
    .isBoolean()
    .withMessage('isActive must be a boolean')
], async (req, res) => {
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
    const { isActive } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent admin from deactivating themselves
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        error: 'Cannot modify your own account status'
      });
    }

    user.isActive = isActive;
    await user.save();

    res.status(200).json({
      success: true,
      data: user,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during status update'
    });
  }
});

// @desc    Update user verification status
// @route   PATCH /api/admin/users/:id/verify
// @access  Private (Admin only)
router.patch('/users/:id/verify', [
  body('isVerified')
    .isBoolean()
    .withMessage('isVerified must be a boolean')
], async (req, res) => {
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
    const { isVerified } = req.body;

    const user = await User.findByIdAndUpdate(
      id,
      { isVerified },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user,
      message: `User verification ${isVerified ? 'confirmed' : 'removed'}`
    });
  } catch (error) {
    console.error('Update verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during verification update'
    });
  }
});

// @desc    Delete user (soft delete)
// @route   DELETE /api/admin/users/:id
// @access  Private (Admin only)
router.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent admin from deleting themselves
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own account'
      });
    }

    // Soft delete by deactivating
    user.isActive = false;
    await user.save();

    // Also deactivate user's complaints
    await Complaint.updateMany(
      { user: id },
      { isActive: false }
    );

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during user deletion'
    });
  }
});

// @desc    Get system statistics
// @route   GET /api/admin/stats
// @access  Private (Admin only)
router.get('/stats', async (req, res) => {
  try {
    const { fromDate, toDate } = req.query;
    
    let dateFilter = {};
    if (fromDate || toDate) {
      dateFilter.createdAt = {};
      if (fromDate) dateFilter.createdAt.$gte = new Date(fromDate);
      if (toDate) dateFilter.createdAt.$lte = new Date(toDate);
    }

    // Complaints statistics
    const complaintStats = await Complaint.getStatistics({ isActive: true, ...dateFilter });
    const departmentStats = await Complaint.getDepartmentStats({ isActive: true, ...dateFilter });

    // User statistics
    const userStats = await User.aggregate([
      { $match: { isActive: true, ...dateFilter } },
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          citizens: { $sum: { $cond: [{ $eq: ['$role', 'citizen'] }, 1, 0] } },
          officers: { $sum: { $cond: [{ $eq: ['$role', 'officer'] }, 1, 0] } },
          admins: { $sum: { $cond: [{ $eq: ['$role', 'admin'] }, 1, 0] } },
          verified: { $sum: { $cond: ['$isVerified', 1, 0] } }
        }
      }
    ]);

    // Monthly trend data
    const monthlyTrend = await Complaint.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 },
          resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } },
      { $limit: 12 }
    ]);

    // Performance metrics
    const performanceStats = await Complaint.aggregate([
      { $match: { isActive: true, status: 'resolved' } },
      {
        $group: {
          _id: '$department',
          avgResolutionTime: {
            $avg: {
              $divide: [
                { $subtract: ['$actualResolutionDate', '$createdAt'] },
                1000 * 60 * 60 * 24
              ]
            }
          },
          totalResolved: { $sum: 1 }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      data: {
        complaints: complaintStats,
        departments: departmentStats,
        users: userStats[0] || { totalUsers: 0, citizens: 0, officers: 0, admins: 0, verified: 0 },
        monthlyTrend,
        performance: performanceStats
      }
    });
  } catch (error) {
    console.error('Get system stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching statistics'
    });
  }
});

// @desc    Bulk operations on complaints
// @route   POST /api/admin/complaints/bulk
// @access  Private (Admin only)
router.post('/complaints/bulk', [
  body('action')
    .isIn(['assign', 'status', 'delete'])
    .withMessage('Invalid bulk action'),
  body('complaintIds')
    .isArray({ min: 1 })
    .withMessage('Please provide at least one complaint ID'),
  body('complaintIds.*')
    .isMongoId()
    .withMessage('Invalid complaint ID format')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation Error',
        details: errors.array()
      });
    }

    const { action, complaintIds, assignTo, status, comment } = req.body;

    let updateResult;
    let message;

    switch (action) {
      case 'assign':
        if (!assignTo) {
          return res.status(400).json({
            success: false,
            error: 'Officer ID required for assignment'
          });
        }
        
        updateResult = await Complaint.updateMany(
          { _id: { $in: complaintIds }, isActive: true },
          { 
            assignedTo: assignTo,
            $push: {
              statusHistory: {
                status: 'acknowledged',
                changedBy: req.user._id,
                comment: comment || 'Bulk assignment',
                timestamp: new Date()
              }
            }
          }
        );
        message = `${updateResult.modifiedCount} complaints assigned successfully`;
        break;

      case 'status':
        if (!status) {
          return res.status(400).json({
            success: false,
            error: 'Status required for status update'
          });
        }
        
        updateResult = await Complaint.updateMany(
          { _id: { $in: complaintIds }, isActive: true },
          { 
            status,
            $push: {
              statusHistory: {
                status,
                changedBy: req.user._id,
                comment: comment || `Bulk status update to ${status}`,
                timestamp: new Date()
              }
            }
          }
        );
        message = `${updateResult.modifiedCount} complaints updated successfully`;
        break;

      case 'delete':
        updateResult = await Complaint.updateMany(
          { _id: { $in: complaintIds } },
          { isActive: false }
        );
        message = `${updateResult.modifiedCount} complaints deleted successfully`;
        break;

      default:
        return res.status(400).json({
          success: false,
          error: 'Invalid action'
        });
    }

    res.status(200).json({
      success: true,
      message,
      affectedCount: updateResult.modifiedCount
    });
  } catch (error) {
    console.error('Bulk operation error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during bulk operation'
    });
  }
});

// @desc    Export complaints data
// @route   GET /api/admin/export/complaints
// @access  Private (Admin only)
router.get('/export/complaints', async (req, res) => {
  try {
    const { format = 'json', fromDate, toDate, status, department } = req.query;

    // Build filters
    const filters = { isActive: true };
    if (fromDate || toDate) {
      filters.createdAt = {};
      if (fromDate) filters.createdAt.$gte = new Date(fromDate);
      if (toDate) filters.createdAt.$lte = new Date(toDate);
    }
    if (status) filters.status = status;
    if (department) filters.department = department;

    const complaints = await Complaint.find(filters)
      .populate('user', 'name email phone')
      .populate('assignedTo', 'name email department')
      .select('-comments -statusHistory -metadata')
      .sort({ createdAt: -1 });

    if (format === 'csv') {
      // Convert to CSV format
      const csvHeader = 'ID,Subject,Type,Status,Priority,User,Email,Phone,Address,Created,Assigned To,Department\n';
      const csvData = complaints.map(complaint => {
        return [
          complaint.complaintId,
          `"${complaint.subject}"`,
          complaint.type,
          complaint.status,
          complaint.priority,
          complaint.user?.name || 'Anonymous',
          complaint.user?.email || '',
          complaint.user?.phone || '',
          `"${complaint.location?.address || ''}"`,
          complaint.createdAt.toISOString().split('T')[0],
          complaint.assignedTo?.name || '',
          complaint.department
        ].join(',');
      }).join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=complaints_${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csvHeader + csvData);
    } else {
      // Return as JSON
      res.status(200).json({
        success: true,
        count: complaints.length,
        data: complaints
      });
    }
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during export'
    });
  }
});

module.exports = router;
