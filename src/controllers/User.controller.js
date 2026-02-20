import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apierror.js";
import { User } from "../models/Auth/console/user.model.js";
import { ConsoleSession } from "../models/Auth/console/consoleSession.js";
import { ApiResponse } from "../utils/apiresponse.js";
import { ValidationHelper } from "../utils/validate.js";
import { logger } from "../utils/Logger.js";
import crypto from "crypto";

const generateAccessandRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        if (!user) {
            logger.error('User not found during token generation', { userId });
            throw ApiError.notFound("User not found");
        }
        
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        
        user.refreshtoken = refreshToken;
        await user.save({ validateBeforeSave: false });

        logger.info('Tokens generated successfully', { userId });
        return { accessToken, refreshToken };
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        logger.error('Token generation failed', { userId, error: error.message });
        throw ApiError.internal("Failed to generate authentication tokens");
    }
};

/**
 * Create user session with device and location tracking
 */
const createUserSession = async (user, req, sessionToken, refreshToken) => {
    try {
        // Extract device information
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const deviceInfo = parseUserAgent(userAgent);
        
        // Get IP address
        const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
        
        // Create session
        const session = new ConsoleSession({
            user_id: user._id,
            session_token: sessionToken,
            refresh_token: refreshToken,
            ip_address: ipAddress,
            user_agent: userAgent,
            device_info: deviceInfo,
            location: await getLocationFromIP(ipAddress),
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            login_method: 'email_password',
            is_active: true
        });

        const savedSession = await session.save();
        
        logger.info('User session created', {
            userId: user._id,
            sessionId: savedSession._id,
            ipAddress,
            deviceType: deviceInfo.device_type
        });

        return savedSession;
    } catch (error) {
        logger.error('Failed to create user session', {
            userId: user._id,
            error: error.message
        });
        throw ApiError.internal("Failed to create user session");
    }
};

/**
 * Parse user agent to extract device information
 */
const parseUserAgent = (userAgent) => {
    const deviceInfo = {
        browser: 'Unknown',
        os: 'Unknown',
        device_type: 'unknown'
    };

    if (!userAgent) return deviceInfo;

    // Browser detection
    if (userAgent.includes('Chrome')) deviceInfo.browser = 'Chrome';
    else if (userAgent.includes('Firefox')) deviceInfo.browser = 'Firefox';
    else if (userAgent.includes('Safari')) deviceInfo.browser = 'Safari';
    else if (userAgent.includes('Edge')) deviceInfo.browser = 'Edge';

    // OS detection
    if (userAgent.includes('Windows')) deviceInfo.os = 'Windows';
    else if (userAgent.includes('Mac')) deviceInfo.os = 'macOS';
    else if (userAgent.includes('Linux')) deviceInfo.os = 'Linux';
    else if (userAgent.includes('Android')) deviceInfo.os = 'Android';
    else if (userAgent.includes('iOS')) deviceInfo.os = 'iOS';

    // Device type detection
    if (userAgent.includes('Mobile') || userAgent.includes('Android')) {
        deviceInfo.device_type = 'mobile';
    } else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
        deviceInfo.device_type = 'tablet';
    } else {
        deviceInfo.device_type = 'desktop';
    }

    return deviceInfo;
};

/**
 * Get location from IP address (placeholder - implement with actual service)
 */
const getLocationFromIP = async (ipAddress) => {
    // Placeholder implementation
    // In production, use services like MaxMind, IPGeolocation, etc.
    return {
        country: 'Unknown',
        city: 'Unknown',
        timezone: 'Unknown'
    };
};

/**
 * Invalidate old sessions for security
 */
const invalidateOldSessions = async (userId, currentSessionId = null) => {
    try {
        const query = { 
            user_id: userId, 
            is_active: true 
        };
        
        // Don't invalidate current session
        if (currentSessionId) {
            query._id = { $ne: currentSessionId };
        }

        const result = await ConsoleSession.updateMany(query, { is_active: false });
        
        logger.info('Old sessions invalidated', {
            userId,
            invalidatedCount: result.modifiedCount
        });
        
        return result.modifiedCount;
    } catch (error) {
        logger.error('Failed to invalidate old sessions', {
            userId,
            error: error.message
        });
        // Don't throw error as this is not critical
        return 0;
    }
};


const userRegister = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    logger.info('User registration attempt', { email });

    // Validate required fields
    ValidationHelper.validateRequired(['name', 'email', 'password'], req.body);

    // Validate input formats
    ValidationHelper.validateEmail(email);
    ValidationHelper.validatePassword(password);
    ValidationHelper.validateStringLength(name, 'name', 2, 50);

    // Sanitize inputs
    const sanitizedName = ValidationHelper.sanitizeInput(name);
    const sanitizedEmail = ValidationHelper.sanitizeInput(email.toLowerCase());

    // Check if user already exists
    const userExist = await User.findOne({ email: sanitizedEmail });
    if (userExist) {
        logger.warn('Registration attempt with existing email', { email: sanitizedEmail });
        throw ApiError.conflict("User already exists with this email");
    }

    // Create user
    const user = await User.create({
        name: sanitizedName,
        email: sanitizedEmail,
        password
    });

    const createdUser = await User.findById(user._id).select("-password -refreshtoken");

    if (!createdUser) {
        logger.error('User creation failed', { email: sanitizedEmail });
        throw ApiError.internal("User registration failed, please try again");
    }

    logger.info('User registered successfully', { 
        userId: createdUser._id, 
        email: sanitizedEmail 
    });

    const response = new ApiResponse(201, createdUser, "User registered successfully");
    return res.status(response.statuscode).json(response);
});


const userLogin = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    logger.info('User login attempt', { 
        email, 
        ip: req.ip, 
        userAgent: req.headers['user-agent'] 
    });

    // Validate required fields
    ValidationHelper.validateRequired(['email', 'password'], req.body);
    ValidationHelper.validateEmail(email);

    // Sanitize email
    const sanitizedEmail = ValidationHelper.sanitizeInput(email.toLowerCase());

    // Find user
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
        logger.warn('Login attempt with non-existent email', { email: sanitizedEmail });
        throw ApiError.unauthorized("Invalid email or password");
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
        logger.warn('Login attempt with invalid password', { 
            userId: user._id, 
            email: sanitizedEmail 
        });
        throw ApiError.unauthorized("Invalid email or password");
    }

    // Generate tokens
    const { accessToken, refreshToken } = await generateAccessandRefreshToken(user._id);

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('hex');

    // Create session with device tracking
    const session = await createUserSession(user, req, sessionToken, refreshToken);

    // Optional: Invalidate old sessions for security (uncomment if needed)
    // await invalidateOldSessions(user._id, session._id);

    // Get user data without sensitive fields
    const loggedInUser = await User.findById(user._id).select("-password -refreshtoken");

    // Cookie options
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'develpoment',
        sameSite: 'strict'
    };

    logger.info('User logged in successfully', {
        userId: user._id,
        sessionId: session._id,
        email: sanitizedEmail,
        deviceType: session.device_info.device_type
    });

    const response = new ApiResponse(
        200,
        {
            user: loggedInUser,
            session: {
                id: session._id,
                expires_at: session.expires_at,
                device_info: session.device_info,
                location: session.location
            },
            tokens: {
                accessToken,
                // Don't send refresh token in response body for security
            }
        },
        "User logged in successfully"
    );

    return res
        .status(response.statuscode)
        .cookie("refreshToken", refreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })
        .cookie("accessToken", accessToken, {
            ...cookieOptions,
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        })
        .cookie("sessionId", sessionToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })
        .json(response);
});

/**
 * Logout user and invalidate session
 */
const userLogout = asyncHandler(async (req, res) => {
    const sessionToken = req.cookies?.sessionId;
    const userId = req.user?.id; // Assuming you have auth middleware that sets req.user

    logger.info('User logout attempt', { userId, hasSessionToken: !!sessionToken });

    if (sessionToken) {
        // Find and invalidate the session
        const session = await ConsoleSession.findOne({ 
            session_token: sessionToken, 
            is_active: true 
        });

        if (session) {
            await session.invalidate();
            logger.info('Session invalidated on logout', { 
                sessionId: session._id, 
                userId: session.user_id 
            });
        }
    }

    // Clear user's refresh token
    if (userId) {
        await User.findByIdAndUpdate(userId, { refreshtoken: null });
    }

    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    };

    logger.info('User logged out successfully', { userId });

    const response = new ApiResponse(200, null, "User logged out successfully");

    return res
        .status(response.statuscode)
        .clearCookie("refreshToken", cookieOptions)
        .clearCookie("accessToken", cookieOptions)
        .clearCookie("sessionId", cookieOptions)
        .json(response);
});

/**
 * Get user's active sessions
 */
const getUserSessions = asyncHandler(async (req, res) => {
    const userId = req.user?.id; // From auth middleware

    if (!userId) {
        throw ApiError.unauthorized("Authentication required");
    }

    const sessions = await ConsoleSession.findActiveSessions(userId);

    const sessionData = sessions.map(session => ({
        id: session._id,
        ip_address: session.ip_address,
        device_info: session.device_info,
        location: session.location,
        login_method: session.login_method,
        last_activity: session.last_activity,
        created_at: session.createdAt,
        is_current: req.cookies?.sessionId === session.session_token
    }));

    logger.info('Retrieved user sessions', { userId, sessionCount: sessions.length });

    const response = new ApiResponse(200, sessionData, "Sessions retrieved successfully");
    return res.status(response.statuscode).json(response);
});

/**
 * Revoke a specific session
 */
const revokeSession = asyncHandler(async (req, res) => {
    const { sessionId } = req.params;
    const userId = req.user?.id;

    ValidationHelper.validateObjectId(sessionId, 'Session ID');

    const session = await ConsoleSession.findOne({
        _id: sessionId,
        user_id: userId,
        is_active: true
    });

    if (!session) {
        throw ApiError.notFound("Session not found");
    }

    await session.invalidate();

    logger.info('Session revoked', { sessionId, userId });

    const response = new ApiResponse(200, null, "Session revoked successfully");
    return res.status(response.statuscode).json(response);
});

export {
    userRegister,
    userLogin,
    userLogout,
    getUserSessions,
    revokeSession
};