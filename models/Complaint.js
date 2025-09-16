const mongoose = require('mongoose');

const complaintSchema = new mongoose.Schema({
  complaintId: {
    type: String,
    unique: true,
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required']
  },
  subject: {
    type: String,
    required: [true, 'Subject is required'],
    trim: true,
    maxlength: [200, 'Subject cannot be more than 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true,
    maxlength: [2000, 'Description cannot be more than 2000 characters']
  },
  type: {
    type: String,
    required: [true, 'Complaint type is required'],
    enum: {
      values: ['Water Supply', 'Electricity', 'Roads', 'Sanitation', 'Public Health', 'Other'],
      message: 'Please select a valid complaint type'
    }
  },
  category: {
    type: String,
    enum: ['urgent', 'normal', 'low'],
    default: 'normal'
  },
  status: {
    type: String,
    enum: {
      values: ['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened'],
      message: 'Please select a valid status'
    },
    default: 'registered'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  location: {
    address: {
      type: String,
      required: [true, 'Address is required'],
      trim: true
    },
    coordinates: {
      latitude: {
        type: Number,
        validate: {
          validator: function(v) {
            return v >= -90 && v <= 90;
          },
          message: 'Latitude must be between -90 and 90'
        }
      },
      longitude: {
        type: Number,
        validate: {
          validator: function(v) {
            return v >= -180 && v <= 180;
          },
          message: 'Longitude must be between -180 and 180'
        }
      }
    },
    pincode: {
      type: String,
      match: [/^\d{6}$/, 'Please provide a valid pincode']
    }
  },
  attachments: [{
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  department: {
    type: String,
    enum: ['water', 'electricity', 'roads', 'sanitation', 'health', 'general'],
    required: true
  },
  statusHistory: [{
    status: {
      type: String,
      enum: ['registered', 'acknowledged', 'in-progress', 'resolved', 'closed', 'reopened']
    },
    changedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    comment: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    message: {
      type: String,
      required: true,
      trim: true,
      maxlength: [1000, 'Comment cannot be more than 1000 characters']
    },
    isPublic: {
      type: Boolean,
      default: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  rating: {
    score: {
      type: Number,
      min: 1,
      max: 5
    },
    feedback: String,
    ratedAt: Date
  },
  expectedResolutionDate: Date,
  actualResolutionDate: Date,
  isAnonymous: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  reopenCount: {
    type: Number,
    default: 0
  },
  tags: [String],
  metadata: {
    source: {
      type: String,
      enum: ['web', 'mobile', 'phone', 'email', 'whatsapp'],
      default: 'web'
    },
    userAgent: String,
    ipAddress: String
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better performance
complaintSchema.index({ complaintId: 1 });
complaintSchema.index({ user: 1 });
complaintSchema.index({ status: 1 });
complaintSchema.index({ type: 1 });
complaintSchema.index({ department: 1 });
complaintSchema.index({ assignedTo: 1 });
complaintSchema.index({ createdAt: -1 });
complaintSchema.index({ 'location.pincode': 1 });

// Text index for search functionality
complaintSchema.index({
  subject: 'text',
  description: 'text',
  'location.address': 'text'
});

// Virtual for days since creation
complaintSchema.virtual('daysSinceCreated').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for resolution time
complaintSchema.virtual('resolutionTime').get(function() {
  if (this.actualResolutionDate && this.createdAt) {
    return Math.floor((this.actualResolutionDate - this.createdAt) / (1000 * 60 * 60 * 24));
  }
  return null;
});

// Pre-save middleware to generate complaint ID
complaintSchema.pre('save', async function(next) {
  if (this.isNew) {
    const year = new Date().getFullYear();
    const month = String(new Date().getMonth() + 1).padStart(2, '0');
    
    // Find the last complaint for this month
    const lastComplaint = await this.constructor
      .findOne({ complaintId: new RegExp(`^BGD${year}${month}`) })
      .sort({ complaintId: -1 });
    
    let sequence = 1;
    if (lastComplaint) {
      const lastSequence = parseInt(lastComplaint.complaintId.slice(-6));
      sequence = lastSequence + 1;
    }
    
    this.complaintId = `BGD${year}${month}${String(sequence).padStart(6, '0')}`;
    
    // Auto-assign department based on complaint type
    const typeMapping = {
      'Water Supply': 'water',
      'Electricity': 'electricity',
      'Roads': 'roads',
      'Sanitation': 'sanitation',
      'Public Health': 'health'
    };
    
    this.department = typeMapping[this.type] || 'general';
    
    // Add initial status to history
    this.statusHistory.push({
      status: this.status,
      comment: 'Complaint registered',
      timestamp: new Date()
    });
  }
  
  next();
});

// Method to add status history
complaintSchema.methods.updateStatus = function(newStatus, changedBy, comment) {
  this.status = newStatus;
  this.statusHistory.push({
    status: newStatus,
    changedBy,
    comment: comment || `Status changed to ${newStatus}`,
    timestamp: new Date()
  });
  
  if (newStatus === 'resolved') {
    this.actualResolutionDate = new Date();
  } else if (newStatus === 'reopened') {
    this.reopenCount += 1;
    this.actualResolutionDate = undefined;
  }
  
  return this.save();
};

// Method to add comment
complaintSchema.methods.addComment = function(userId, message, isPublic = true) {
  this.comments.push({
    user: userId,
    message,
    isPublic,
    timestamp: new Date()
  });
  
  return this.save();
};

// Method to add rating
complaintSchema.methods.addRating = function(score, feedback) {
  this.rating = {
    score,
    feedback,
    ratedAt: new Date()
  };
  
  return this.save();
};

// Static method to get complaint statistics
complaintSchema.statics.getStatistics = async function(filters = {}) {
  const pipeline = [
    { $match: filters },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        registered: { $sum: { $cond: [{ $eq: ['$status', 'registered'] }, 1, 0] } },
        acknowledged: { $sum: { $cond: [{ $eq: ['$status', 'acknowledged'] }, 1, 0] } },
        inProgress: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
        resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
        closed: { $sum: { $cond: [{ $eq: ['$status', 'closed'] }, 1, 0] } },
        reopened: { $sum: { $cond: [{ $eq: ['$status', 'reopened'] }, 1, 0] } },
        avgResolutionTime: { 
          $avg: {
            $cond: [
              { $ne: ['$actualResolutionDate', null] },
              { $divide: [{ $subtract: ['$actualResolutionDate', '$createdAt'] }, 1000 * 60 * 60 * 24] },
              null
            ]
          }
        }
      }
    }
  ];
  
  const result = await this.aggregate(pipeline);
  return result[0] || { total: 0 };
};

// Static method for department-wise statistics
complaintSchema.statics.getDepartmentStats = async function(filters = {}) {
  const pipeline = [
    { $match: filters },
    {
      $group: {
        _id: '$department',
        count: { $sum: 1 },
        resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
        pending: { $sum: { $cond: [{ $ne: ['$status', 'resolved'] }, 1, 0] } }
      }
    },
    { $sort: { count: -1 } }
  ];
  
  return await this.aggregate(pipeline);
};

module.exports = mongoose.model('Complaint', complaintSchema);
