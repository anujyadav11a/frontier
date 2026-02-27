import mongoose, { Schema } from "mongoose";
import crypto from "crypto";

const projectSchema = new Schema({
    // Basic Project Information
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 2,
        maxlength: 100
    },
    description: {
        type: String,
        trim: true,
        maxlength: 500
    },
    
    // Project Owner
    owner_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true
    },

    // Project ID for SDK (unique identifier)
    project_id: {
        type: String,
        unique: true,
        index: true
    },

    // API Key for authentication
    api_key: {
        type: String,
        unique: true,
        index: true
    },

    // Project Status
    status: {
        type: String,
        enum: ['active', 'suspended', 'deleted'],
        default: 'active',
        index: true
    },

    // Basic Configuration
    config: {
        // Database Configuration
        max_databases: {
            type: Number,
            default: 3
        },
        max_tables_per_db: {
            type: Number,
            default: 10
        },
        max_documents_per_table: {
            type: Number,
            default: 1000
        },
        
        // API Configuration
        cors_origins: [{
            type: String,
            default: '*'
        }]
    },

    // Usage Statistics (simple)
    usage_stats: {
        api_requests_count: {
            type: Number,
            default: 0
        },
        storage_used_mb: {
            type: Number,
            default: 0
        }
    }

}, {
    timestamps: true
});

// Indexes for performance
projectSchema.index({ owner_id: 1, status: 1 });
projectSchema.index({ createdAt: -1 });


// Virtual for SDK config info
projectSchema.virtual('sdk_config').get(function() {
    return {
        project_id: this.project_id,
        api_key: this.api_key,
        api_endpoint: `${process.env.API_BASE_URL || 'http://localhost:8000'}/api/v1/${this.project_id}`
    };
});

// Methods
projectSchema.methods.generateProjectId = function() {
    // Generate a unique project ID (8 characters)
    return crypto.randomBytes(4).toString('hex');
};

projectSchema.methods.generateApiKey = function() {
    // Generate a secure API key (32 characters)
    return crypto.randomBytes(16).toString('hex');
};

projectSchema.methods.updateUsage = function(type, amount = 1) {
    switch (type) {
        case 'api_request':
            this.usage_stats.api_requests_count += amount;
            break;
        case 'storage':
            this.usage_stats.storage_used_mb += amount;
            break;
    }
    return this.save();
};

projectSchema.methods.isWithinLimits = function() {
    // Simple limit checking
    return {
        api_requests: this.usage_stats.api_requests_count < 10000, // 10k requests limit
        storage: this.usage_stats.storage_used_mb < 100 // 100MB limit
    };
};

// Static methods
projectSchema.statics.findByProjectId = function(project_Id) {
    return this.findOne({ project_id: project_Id, status: 'active' }).lean();
};

projectSchema.statics.findByApiKey = function(api_Key) {
    return this.findOne({ api_key: api_Key, status: 'active' }).lean();
};

projectSchema.statics.findByOwner = function(owner_Id) {
    return this.find({ owner_id: owner_Id, status: { $ne: 'deleted' } }).lean();
};

// Pre-save middleware
projectSchema.pre('save', async function() {
    // Generate project_id and api_key if new project
    if (this.isNew) {
        // Generate unique project ID
        let projectId;
        let isUnique = false;
        
        while (!isUnique) {
            projectId = this.generateProjectId();
            const existing = await this.constructor.findOne({ project_id: projectId });
            if (!existing) {
                isUnique = true;
            }
        }
        
        this.project_id = projectId;
        this.api_key = this.generateApiKey();
    }
});

export const Project = mongoose.model("Project", projectSchema);