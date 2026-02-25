import mongoose, { Schema } from 'mongoose';

/**
 * Tenant User Session Model
 * 
 * Tracks active sessions for tenant users across different devices/browsers.
 * Helps with security, analytics, and session management.
 * 
 * Use Cases:
 * - Track user login sessions
 * - Implement "logout from all devices"
 * - Monitor suspicious login activity
 * - Analytics on user engagement
 */

const tenantSessionSchema = new Schema({
    // User Reference
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'TenantUser',
        required: true,
        index: true
    },
    
    // Project Reference (for quick filtering)
    project_id: {
        type: String,
        required: true,
        index: true
    },
    
    
    
    // JWT Token Information
    refresh_token: {
        type: String,
        required: true,
        unique: true
    },
   
    
    // Session Metadata
    device_info: {
        user_agent: {
            type: String,
            maxlength: 500
        },
        browser: {
            type: String,
            maxlength: 100
        },
        os: {
            type: String,
            maxlength: 100
        },
        device_type: {
            type: String,
            enum: ['desktop', 'mobile', 'tablet', 'unknown'],
            default: 'unknown'
        }
    },
    
    // Location Information (optional)
    location: {
        ip_address: {
            type: String,
            required: true
        },
        country: {
            type: String,
            maxlength: 100
        },
        city: {
            type: String,
            maxlength: 100
        },
        timezone: {
            type: String,
            maxlength: 50
        }
    },
    
    // Session Status
    status: {
        type: String,
        enum: ['active', 'expired', 'revoked', 'suspicious'],
        default: 'active',
        index: true
    },
    
    // Session Timing
    login_time: {
        type: Date,
        default: Date.now,
        required: true
    },
    last_activity: {
        type: Date,
        default: Date.now,
        required: true
    },
    expires_at: {
        type: Date,
        required: true,
        index: true  // For cleanup of expired sessions
    },
    logout_time: {
        type: Date  // Set when user logs out
    },
    
    
    
   
    
}, {
    timestamps: true
});

// Indexes for performance
sessionSchema.index({ user_id: 1, is_active: 1 });
sessionSchema.index({ last_activity: 1 });

// Virtual for session duration
tenantSessionSchema.virtual('duration_minutes').get(function() {
    const endTime = this.logout_time || this.last_activity || new Date();
    const startTime = this.login_time;
    return Math.round((endTime - startTime) / (1000 * 60)); // Duration in minutes
});

// Virtual for checking if session is still valid
tenantSessionSchema.virtual('is_valid').get(function() {
    return this.status === 'active' && this.expires_at > new Date();
});

// Pre-save Middleware
tenantSessionSchema.pre('save', function(next) {
    // Update last_activity when session is modified
    if (this.isModified() && !this.isModified('last_activity')) {
        this.last_activity = new Date();
    }
    next();
});

// Instance Methods

/**
 * Generate unique session ID
 * @returns {string} - Unique session identifier
 */
tenantSessionSchema.methods.generateSessionId = function() {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
};








// Static Methods


tenantSessionSchema.statics.createSession = async function(sessionData) {
    const crypto = require('crypto');
    
    const session = new this({
        user_id: sessionData.user_id,
        project_id: sessionData.project_id,
        session_id: crypto.randomBytes(32).toString('hex'),
        refresh_token: sessionData.refresh_token,
        device_info: sessionData.device_info || {},
        location: sessionData.location || {},
        expires_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)) // 7 days default
    });
    
    return await session.save();
};


tenantSessionSchema.statics.findActiveSessions = function(userId) {
    return this.find({
        user_id: userId,
        status: 'active',
        expires_at: { $gt: new Date() }
    }).sort({ last_activity: -1 });
};




/**
 * Clean up expired sessions (for scheduled cleanup)
 * @param {number} daysOld - Remove sessions older than X days (default: 30)
 */
tenantSessionSchema.statics.cleanupExpiredSessions = async function(daysOld = 30) {
    const cutoffDate = new Date(Date.now() - (daysOld * 24 * 60 * 60 * 1000));
    
    return await this.deleteMany({
        $or: [
            { expires_at: { $lt: new Date() } }, // Expired sessions
            { 
                status: { $in: ['revoked', 'expired'] },
                updatedAt: { $lt: cutoffDate }
            }
        ]
    });
};



// Export the model
export const TenantSession = mongoose.model('TenantSession', tenantSessionSchema);