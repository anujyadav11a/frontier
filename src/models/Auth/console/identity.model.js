import mongoose, { Schema } from "mongoose";
import crypto from "crypto";

const identitySchema = new Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true
    },
    provider: {
        type: String,
        required: true,
        enum: ['google', 'github', 'microsoft', 'facebook', 'linkedin'],
        index: true
    },
    provider_id: {
        type: String,
        required: true,
        index: true
    },
    provider_email: {
        type: String,
        required: true
    },
    provider_name: {
        type: String
    },

   
    refresh_token: {
        type: String
    },
    expires_at: {
        type: Date
    },
    scope: {
        type: [String],
        default: []
    },

    is_active: {
        type: Boolean,
        default: true
    },
    is_primary: {
        type: Boolean,
        default: false
    },
    last_used: {
        type: Date,
        default: Date.now
    },

    provider_data: {
        type: Map,
        of: mongoose.Schema.Types.Mixed,
        default: {}
    }

}, { timestamps: true });


// Compound indexes for performance and uniqueness
identitySchema.index({ provider: 1, provider_id: 1 }, { unique: true });
identitySchema.index({ user_id: 1, provider: 1 });
identitySchema.index({ user_id: 1, is_primary: 1 });
identitySchema.index({ expires_at: 1 });

// Virtual for checking if refresh token is expired
identitySchema.virtual('is_token_expired').get(function() {
    if (!this.expires_at) return false;
    return new Date() > this.expires_at;
});

// Methods
identitySchema.methods.isRefreshTokenValid = function() {
    return this.is_active && !this.is_token_expired && this.refresh_token;
};

identitySchema.methods.updateLastUsed = function() {
    this.last_used = new Date();
    return this.save();
};

identitySchema.methods.getAccessToken = async function() {
    // This method would typically call the OAuth provider's token endpoint
    // to exchange the refresh_token for a new access_token
    if (!this.isRefreshTokenValid()) {
        throw new Error('Invalid or expired refresh token');
    }
    
    // Return the refresh token for external token exchange
    // The actual access token request should be handled by the service layer
    return {
        refresh_token: this.refresh_token,
        provider: this.provider,
        expires_at: this.expires_at
    };
};

identitySchema.methods.updateTokenData = async function(newTokenData) {
    if (newTokenData.refresh_token) {
        this.refresh_token = newTokenData.refresh_token;
    }
    if (newTokenData.expires_in) {
        this.expires_at = new Date(Date.now() + (newTokenData.expires_in * 1000));
    }
    if (newTokenData.scope) {
        this.scope = Array.isArray(newTokenData.scope) ? newTokenData.scope : newTokenData.scope.split(' ');
    }
    this.updatedAt = new Date();
    return this.save();
};

identitySchema.methods.revoke = function() {
    this.is_active = false;
    return this.save();
};

identitySchema.methods.encryptSensitiveData = function() {
    // Encrypt refresh_token before saving
    if (this.refresh_token && !this.refresh_token.startsWith('enc:')) {
        this.refresh_token = 'enc:' + this.encrypt(this.refresh_token);
    }
};

identitySchema.methods.decryptSensitiveData = function() {
    // Decrypt refresh_token after retrieval
    if (this.refresh_token && this.refresh_token.startsWith('enc:')) {
        this.refresh_token = this.decrypt(this.refresh_token.substring(4));
    }
};

identitySchema.methods.encrypt = function(text) {
    const algorithm = 'aes-256-gcm';
    const secretKey = process.env.OAUTH_ENCRYPTION_KEY || 'default-key-change-in-production';
    const key = crypto.scryptSync(secretKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, key);
    cipher.setAAD(Buffer.from('oauth-identity', 'utf8'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
};

identitySchema.methods.decrypt = function(encryptedText) {
    const algorithm = 'aes-256-gcm';
    const secretKey = process.env.OAUTH_ENCRYPTION_KEY || 'default-key-change-in-production';
    const key = crypto.scryptSync(secretKey, 'salt', 32);
    
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipher(algorithm, key);
    decipher.setAAD(Buffer.from('oauth-identity', 'utf8'));
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
};

// Static methods
identitySchema.statics.findByProvider = function(provider, providerId) {
    return this.findOne({ provider, provider_id: providerId, is_active: true });
};

identitySchema.statics.findByUser = function(userId) {
    return this.find({ user_id: userId, is_active: true });
};

identitySchema.statics.findPrimaryIdentity = function(userId) {
    return this.findOne({ user_id: userId, is_primary: true, is_active: true });
};

identitySchema.statics.setPrimaryIdentity = async function(userId, identityId) {
    // Remove primary flag from all identities for this user
    await this.updateMany(
        { user_id: userId },
        { is_primary: false }
    );
    
    // Set the specified identity as primary
    return this.findByIdAndUpdate(
        identityId,
        { is_primary: true },
        { new: true }
    );
};

identitySchema.statics.cleanupExpiredRefreshTokens = function() {
    return this.updateMany(
        { 
            expires_at: { $lt: new Date() },
            is_active: true 
        },
        { is_active: false }
    );
};

identitySchema.statics.revokeAllUserIdentities = function(userId) {
    return this.updateMany(
        { user_id: userId, is_active: true },
        { is_active: false }
    );
};

// Pre-save middleware for encryption
identitySchema.pre('save', function(next) {
    if (this.isModified('refresh_token')) {
        this.encryptSensitiveData();
    }
    next();
});

// Post-find middleware for decryption
identitySchema.post(['find', 'findOne', 'findOneAndUpdate'], function(docs) {
    if (!docs) return;
    
    const decrypt = (doc) => {
        if (doc && typeof doc.decryptSensitiveData === 'function') {
            doc.decryptSensitiveData();
        }
    };
    
    if (Array.isArray(docs)) {
        docs.forEach(decrypt);
    } else {
        decrypt(docs);
    }
});

export const Identity = mongoose.model("Identity", identitySchema);