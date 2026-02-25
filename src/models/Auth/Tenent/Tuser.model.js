import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

/**
 * Tenant User Model
 * 
 * Tenant users are end-users of applications built using our database service.
 * They authenticate using API keys provided by console users (project owners).
 * 
 * Flow:
 * 1. Console user creates a project → gets project_id + api_key
 * 2. Console user shares credentials with their app
 * 3. App users register/login as tenant users using those credentials
 */

const tenantUserSchema = new Schema({
    // Basic User Information
    username: {
        type: String,
        required: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    
    // Project Association (which project this user belongs to)
    project_id: {
        type: String,
        required: true,
        index: true  // For fast lookups
    },
    
    
    // User Status
    status: {
        type: String,
        enum: ['active', 'inactive', 'suspended'],
        default: 'active'
    },
    
    
    
}, {
    timestamps: true  // Adds createdAt and updatedAt
});

// Indexes for Performance
tenantUserSchema.index({ project_id: 1, email: 1 }, { unique: true }); // Unique email per project
tenantUserSchema.index({ project_id: 1, username: 1 }, { unique: true }); // Unique username per project
tenantUserSchema.index({ project_id: 1, status: 1 }); // For filtering active users

// Virtual for full name
tenantUserSchema.virtual('full_name').get(function() {
    if (this.profile.first_name && this.profile.last_name) {
        return `${this.profile.first_name} ${this.profile.last_name}`;
    }
    return this.username;
});

// Pre-save Middleware - Hash password before saving
tenantUserSchema.pre('save', async function(next) {
    // Only hash password if it's modified (new or changed)
    if (!this.isModified('password')) return next();
    
    try {
        // Hash password with salt rounds of 10
        this.password = await bcrypt.hash(this.password, 10);
        next();
    } catch (error) {
        next(error);
    }
});

// Instance Methods


tenantUserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

/**
 * Generate JWT access token (short-lived)
 * @returns {string} - JWT access token
 */
tenantUserSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            _id: this._id,
            username: this.username,
            email: this.email,
            project_id: this.project_id,
            type: 'tenant_user'  // Distinguish from console users
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_LIFE || '15m'
        }
    );
};

/**
 * Generate JWT refresh token (long-lived)
 * @returns {string} - JWT refresh token
 */
tenantUserSchema.methods.generateRefreshToken = function() {
    return jwt.sign(
        {
            _id: this._id,
            project_id: this.project_id,
            type: 'tenant_user'
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_LIFE || '7d'
        }
    );
};




// Static Methods


tenantUserSchema.statics.findByProjectAndEmail = function(projectId, email) {
    return this.findOne({ 
        project_id: projectId, 
        email: email.toLowerCase(),
        status: 'active'
    });
};

/**
 * Find user by username within a specific project
 * @param {string} projectId - Project ID
 * @param {string} username - Username
 * @returns {Object|null} - User document or null
 */
tenantUserSchema.statics.findByProjectAndUsername = function(projectId, username) {
    return this.findOne({ 
        project_id: projectId, 
        username: username,
        status: 'active'
    });
};



/**
 * Count users in a project
 * @param {string} projectId - Project ID
 * @returns {number} - User count
 */
tenantUserSchema.statics.countByProject = function(projectId) {
    return this.countDocuments({ 
        project_id: projectId,
        status: 'active'
    });
};

// Export the model
export const TenantUser = mongoose.model('TenantUser', tenantUserSchema);