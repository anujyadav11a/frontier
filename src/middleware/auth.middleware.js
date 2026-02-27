import jwt from 'jsonwebtoken';
import { User } from '../models/Auth/console/user.model.js';
import { ConsoleSession } from '../models/Auth/console/consoleSession.js';
import { ApiError } from '../utils/apierror.js';
import { logger } from '../utils/Logger.js';
import { asyncHandler } from '../utils/asyncHandler.js';

export const authMiddleware = asyncHandler(async (req, res, next) => {
    try {
        // Get token from cookies or Authorization header
        const token = req.cookies?.accessToken || 
                     req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw ApiError.unauthorized("Access token is required");
        }

        // Verify JWT token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        
        // Find user
        const user = await User.findById(decodedToken._id).select("-password -refreshtoken");
        if (!user) {
            logger.warn('Token valid but user not found', { userId: decodedToken._id });
            throw ApiError.unauthorized("Invalid access token");
        }

        // Optional: Verify session is still active
        const sessionToken = req.cookies?.sessionId;
        if (sessionToken) {
            const session = await ConsoleSession.findOne({
                session_token: sessionToken,
                user_id: user._id,
                is_active: true
            });

            if (!session || session.isExpired()) {
                logger.warn('Session expired or invalid', { 
                    userId: user._id, 
                    sessionToken: sessionToken?.substring(0, 8) + '...' 
                });
                throw ApiError.unauthorized("Session expired");
            }

            // Update last activity
            await session.updateActivity();
            req.session = session;
        }

        // Attach user to request
        req.user = user;
        next();

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            logger.warn('Invalid JWT token', { error: error.message });
            throw ApiError.unauthorized("Invalid access token");
        }
        
        if (error.name === 'TokenExpiredError') {
            logger.warn('JWT token expired', { error: error.message });
            throw ApiError.unauthorized("Access token expired");
        }

        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('Authentication middleware error', { error: error.message });
        throw ApiError.internal("Authentication failed");
    }
});

/**
 * Optional middleware to check if user has specific role
 */
export const requireRole = (roles) => {
    return asyncHandler(async (req, res, next) => {
        if (!req.user) {
            throw ApiError.unauthorized("Authentication required");
        }

        const userRoles = Array.isArray(roles) ? roles : [roles];
        
        if (!userRoles.includes(req.user.role)) {
            logger.warn('Insufficient permissions', { 
                userId: req.user._id, 
                userRole: req.user.role, 
                requiredRoles: userRoles 
            });
            throw ApiError.forbidden("Insufficient permissions");
        }

        next();
    });
};

/**
 * Middleware to refresh token if it's about to expire
 */
export const refreshTokenMiddleware = asyncHandler(async (req, res, next) => {
    const refreshToken = req.cookies?.refreshToken;
    
    if (!refreshToken) {
        return next();
    }

    try {
        const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedRefreshToken._id);

        if (user && user.refreshtoken === refreshToken) {
            // Check if access token is about to expire (within 5 minutes)
            const accessToken = req.cookies?.accessToken;
            if (accessToken) {
                const decodedAccessToken = jwt.decode(accessToken);
                const timeUntilExpiry = decodedAccessToken.exp * 1000 - Date.now();
                
                if (timeUntilExpiry < 5 * 60 * 1000) { // Less than 5 minutes
                    // Generate new access token
                    const newAccessToken = user.generateAccessToken();
                    
                    res.cookie("accessToken", newAccessToken, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: 'strict',
                        maxAge: 24 * 60 * 60 * 1000 // 1 day
                    });

                    logger.info('Access token refreshed', { userId: user._id });
                }
            }
        }
    } catch (error) {
        // If refresh token is invalid, just continue
        logger.debug('Refresh token validation failed', { error: error.message });
    }

    next();
});