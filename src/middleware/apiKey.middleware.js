import { Project } from '../models/Database/project.model.js';
import { ApiError } from '../utils/apierror.js';
import { logger } from '../utils/Logger.js';
import { asyncHandler } from '../utils/asyncHandler.js';

/**
 * Middleware to authenticate API key for BaaS API access
 */
export const apiKeyAuth = asyncHandler(async (req, res, next) => {
    try {
        // Get API key from header
        const apiKey = req.header('X-API-Key') || req.header('Authorization')?.replace('Bearer ', '');

        if (!apiKey) {
            throw ApiError.unauthorized('API key is required');
        }

        // Parse API key format: project.keyId.secret
        const keyParts = apiKey.split('.');
        if (keyParts.length !== 3) {
            throw ApiError.unauthorized('Invalid API key format');
        }

        const [projectSlug] = keyParts;

        // Find project by slug
        const project = await Project.findBySlug(projectSlug);
        if (!project) {
            logger.warn('API key used for non-existent project', { projectSlug });
            throw ApiError.unauthorized('Invalid API key');
        }

        // Check project status
        if (project.status !== 'active') {
            logger.warn('API key used for inactive project', { 
                projectId: project._id, 
                status: project.status 
            });
            throw ApiError.forbidden('Project is not active');
        }

        // Validate API key
        const validatedKey = project.validateApiKey(apiKey);
        if (!validatedKey) {
            logger.warn('Invalid API key used', { 
                projectId: project._id,
                keyId: keyParts[1]
            });
            throw ApiError.unauthorized('Invalid API key');
        }

       

        // Update usage statistics
        await project.updateUsageStats('api_request');

        // Attach project and API key info to request
        req.project = project;
        req.apiKey = validatedKey;
        req.rateLimitInfo = rateLimitResult;

        logger.info('API key authenticated successfully', {
            projectId: project._id,
            keyId: validatedKey.key_id,
            environment: validatedKey.environment,
            ip: req.ip
        });

        next();

    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('API key authentication error', {
            error: error.message,
            stack: error.stack
        });
        throw ApiError.internal('Authentication failed');
    }
});

/**
 * Middleware to check specific API permissions
 */
export const requireApiPermission = (permission) => {
    return asyncHandler(async (req, res, next) => {
        if (!req.apiKey) {
            throw ApiError.unauthorized('API key authentication required');
        }

        const hasPermission = req.apiKey.permissions.includes(permission) || 
                            req.apiKey.permissions.includes('admin') ||
                            req.apiKey.permissions.includes('*');

        if (!hasPermission) {
            logger.warn('Insufficient API permissions', {
                projectId: req.project._id,
                keyId: req.apiKey.key_id,
                requiredPermission: permission,
                availablePermissions: req.apiKey.permissions
            });
            throw ApiError.forbidden(`Insufficient permissions. Required: ${permission}`);
        }

        next();
    });
};

/**
 * Middleware to check environment-specific access
 */
export const requireEnvironment = (allowedEnvironments) => {
    return asyncHandler(async (req, res, next) => {
        if (!req.apiKey) {
            throw ApiError.unauthorized('API key authentication required');
        }

        const environments = Array.isArray(allowedEnvironments) ? allowedEnvironments : [allowedEnvironments];
        
        if (!environments.includes(req.apiKey.environment)) {
            logger.warn('Environment access denied', {
                projectId: req.project._id,
                keyId: req.apiKey.key_id,
                keyEnvironment: req.apiKey.environment,
                allowedEnvironments: environments
            });
            throw ApiError.forbidden(`Access denied for ${req.apiKey.environment} environment`);
        }

        next();
    });
};



