import mongoose, { Schema } from "mongoose";

const sessionSchema = new Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true
    },
    session_token: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    refresh_token: {
        type: String,
        required: true,
        unique: true
    },
    ip_address: {
        type: String,
        required: true
    },
    user_agent: {
        type: String,
        required: true
    },
    device_info: {
        browser: String,
        os: String,
        device_type: {
            type: String,
            enum: ['desktop', 'mobile', 'tablet', 'unknown'],
            default: 'unknown'
        }
    },
    location: {
        country: String,
        city: String,
        timezone: String
    },
    is_active: {
        type: Boolean,
        default: true
    },
    last_activity: {
        type: Date,
        default: Date.now
    },
    expires_at: {
        type: Date,
        required: true,
        index: { expireAfterSeconds: 0 }
    },
    login_method: {
        type: String,
        enum: ['email_password', 'oauth', 'sso'],
        default: 'email_password'
    },
    session_data: {
        type: Map,
        of: mongoose.Schema.Types.Mixed,
        default: new Map()
    }
}, {
    timestamps: true
});

// Indexes for performance
sessionSchema.index({ user_id: 1, is_active: 1 });
sessionSchema.index({ expires_at: 1 });
sessionSchema.index({ last_activity: 1 });

// Methods
sessionSchema.methods.isExpired = function() {
    return new Date() > this.expires_at;
};

sessionSchema.methods.updateActivity = function() {
    this.last_activity = new Date();
    return this.save();
};

sessionSchema.methods.invalidate = function() {
    this.is_active = false;
    return this.save();
};

// Static methods
sessionSchema.statics.findActiveSessions = function(userId) {
    return this.find({
        user_id: userId,
        is_active: true,
        expires_at: { $gt: new Date() }
    });
};

sessionSchema.statics.invalidateAllUserSessions = function(userId) {
    return this.updateMany(
        { user_id: userId, is_active: true },
        { is_active: false }
    );
};

sessionSchema.statics.cleanupExpiredSessions = function() {
    return this.deleteMany({
        $or: [
            { expires_at: { $lt: new Date() } },
            { is_active: false }
        ]
    });
};

export const ConsoleSession = mongoose.model("ConsoleSession", sessionSchema);