import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apierror.js";
import { TenantUser } from "../models/Auth/Tenent/Tuser.model.js";
import { TenantSession } from "../models/Auth/Tenent/Tsession.model.js";
import { Project } from "../models/Database/project.model.js";
import { ApiResponse } from "../utils/apiresponse.js";
import { ValidationHelper } from "../utils/validate.js";
import { logger } from "../utils/Logger.js";
import { parseUserAgent,getLocationFromIP } from "./User.controller.js";


/**
 * Generate access and refresh tokens for tenant user
 */
const generateAccessandRefreshToken = async (userId) => {
    try {
        const user = await TenantUser.findById(userId);
        if (!user) {
            logger.error('Tenant user not found during token generation', { userId });
            throw ApiError.notFound("User not found");
        }
        
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        
        // Note: TenantUser doesn't store refresh token in user document
        // It's stored in TenantSession model instead
        
        logger.info('Tenant tokens generated successfully', { userId, projectId: user.project_id });
        return { accessToken, refreshToken };
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        logger.error('Tenant token generation failed', { userId, error: error.message });
        throw ApiError.internal("Failed to generate authentication tokens");
    }
};


/**
 * Create tenant user session with device and location tracking
 */
const createTenantSession = async (user, req, refreshToken) => {
    try {
        // Extract device information
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const deviceInfo = parseUserAgent(userAgent);

        // Get IP address
        const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';

        // Get location data and ensure ip_address is included
        const locationData = await getLocationFromIP(ipAddress);

        // Create session
        const sessionData = {
            user_id: user._id,
            project_id: user.project_id,
            refresh_token: refreshToken,
            device_info: deviceInfo,
            location: {
                ip_address: ipAddress,
                ...locationData
            }
        };

        const session = await TenantSession.createSession(sessionData);

        logger.info('Tenant session created', {
            userId: user._id,
            projectId: user.project_id,
            sessionId: session._id,
            ipAddress,
            deviceType: deviceInfo.device_type
        });

        return session;
    } catch (error) {
        logger.error('Failed to create tenant session', {
            userId: user._id,
            projectId: user.project_id,
            error: error.message
        });
        throw ApiError.internal("Failed to create user session");
    }
}

/**
 * Register tenant user
 */
const tenantRegister = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    const { project_id, api_key} = req.headers;
    // Also try reading uppercase versions as fallback
    const projectId = project_id || req.headers['PROJECT_ID'] || req.headers['project-id'] || req.headers['x-frontier-project-id'];
    const apiKey = api_key || req.headers['API_KEY'] || req.headers['api-key'] || req.headers['x-frontier-api-key'];

    // Validate required fields
    ValidationHelper.validateRequired(['username', 'email', 'password'], req.body);
    ValidationHelper.validateRequired(['project_id', 'api_key'], { project_id: projectId, api_key: apiKey });
     
    // Validate input formats
    ValidationHelper.validateEmail(email);
    ValidationHelper.validatePassword(password);
    ValidationHelper.validateStringLength(username, 'username', 3, 30);

    // Sanitize inputs
    const sanitizedUsername = ValidationHelper.sanitizeInput(username);
    const sanitizedEmail = ValidationHelper.sanitizeInput(email.toLowerCase());

    // Verify project exists and API key is valid
    const project = await Project.findOne({ 
        project_id: projectId, 
        api_key: apiKey, 
        status: 'active' 
    });
    
    if (!project) {
        logger.warn('Registration attempt with invalid project credentials', { 
            project_id: projectId, 
            email: sanitizedEmail 
        });
        throw ApiError.unauthorized("Invalid project credentials");
    }

    // Check if user already exists in this project
    const userExist = await TenantUser.findByProjectAndEmail(projectId, sanitizedEmail);
    if (userExist) {
        logger.warn('Registration attempt with existing email in project', { 
            email: sanitizedEmail, 
            project_id: projectId 
        });
        throw ApiError.conflict("User already exists with this email in this project");
    }

    // Check if username is taken in this project
    const usernameExist = await TenantUser.findByProjectAndUsername(projectId, sanitizedUsername);
    if (usernameExist) {
        logger.warn('Registration attempt with existing username in project', { 
            username: sanitizedUsername, 
            project_id: projectId 
        });
        throw ApiError.conflict("Username already taken in this project");
    }

    // Create tenant user
    const user = await TenantUser.create({
        username: sanitizedUsername,
        email: sanitizedEmail,
        password,
        project_id: projectId
    });

    const createdUser = await TenantUser.findById(user._id).select("-password");

    if (!createdUser) {
        logger.error('Tenant user creation failed', { email: sanitizedEmail, project_id });
        throw ApiError.internal("User registration failed, please try again");
    }

    logger.info('Tenant user registered successfully', { 
        userId: createdUser._id, 
        email: sanitizedEmail,
        project_id: projectId
    });

    const response = new ApiResponse(201, createdUser, "User registered successfully");
    return res.status(response.statuscode).json(response);
});

/**
 * Login tenant user
 */
const tenantLogin = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const { project_id, api_key } = req.headers;

    logger.info('Tenant user login attempt', { 
        email, 
        project_id,
        ip: req.ip, 
        userAgent: req.headers['user-agent'] 
    });

    // Validate required fields
    ValidationHelper.validateRequired(['email', 'password'], req.body);
    ValidationHelper.validateRequired(['project_id', 'api_key'], req.headers);
    ValidationHelper.validateEmail(email);

    // Sanitize email
    const sanitizedEmail = ValidationHelper.sanitizeInput(email.toLowerCase());

    // Verify project exists and API key is valid
    const project = await Project.findOne({ 
        project_id: project_id, 
        api_key: api_key, 
        status: 'active' 
    });
    
    if (!project) {
        logger.warn('Login attempt with invalid project credentials', { 
            project_id, 
            email: sanitizedEmail 
        });
        throw ApiError.unauthorized("Invalid project credentials");
    }

    // Find user in the specific project
    const user = await TenantUser.findByProjectAndEmail(project_id, sanitizedEmail);
    if (!user) {
        logger.warn('Login attempt with non-existent email in project', { 
            email: sanitizedEmail, 
            project_id 
        });
        throw ApiError.unauthorized("Invalid email or password");
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
        logger.warn('Login attempt with invalid password', { 
            userId: user._id, 
            email: sanitizedEmail,
            project_id
        });
        throw ApiError.unauthorized("Invalid email or password");
    }

    // Generate tokens
    const { accessToken, refreshToken } = await generateAccessandRefreshToken(user._id);

    // Create session with device tracking
    const session = await createTenantSession(user, req, refreshToken);

    // Get user data without sensitive fields
    const loggedInUser = await TenantUser.findById(user._id).select("-password");

    // Cookie options
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    };

    logger.info('Tenant user logged in successfully', {
        userId: user._id,
        sessionId: session._id,
        email: sanitizedEmail,
        project_id,
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
        .cookie("tenantRefreshToken", refreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })
        .cookie("tenantAccessToken", accessToken, {
            ...cookieOptions,
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        })
        .json(response);
});

/**
 * Logout tenant user and invalidate session
 */
const tenantLogout = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies?.tenantRefreshToken;
    const userId = req.user?.id; // Assuming you have tenant auth middleware that sets req.user

    logger.info('Tenant user logout attempt', { userId, hasRefreshToken: !!refreshToken });

    if (refreshToken) {
        // Find and invalidate the session
        const session = await TenantSession.findOne({ 
            refresh_token: refreshToken, 
            status: 'active' 
        });

        if (session) {
            session.status = 'revoked';
            session.logout_time = new Date();
            await session.save();
            
            logger.info('Tenant session invalidated on logout', { 
                sessionId: session._id, 
                userId: session.user_id,
                projectId: session.project_id
            });
        }
    }

    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    };

    logger.info('Tenant user logged out successfully', { userId });

    const response = new ApiResponse(200, null, "User logged out successfully");

    return res
        .status(response.statuscode)
        .clearCookie("tenantRefreshToken", cookieOptions)
        .clearCookie("tenantAccessToken", cookieOptions)
        .json(response);
});

/**
 * Get tenant user's active sessions
 */
const getTenantSessions = asyncHandler(async (req, res) => {
    const userId = req.user?.id; // From tenant auth middleware

    if (!userId) {
        throw ApiError.unauthorized("Authentication required");
    }

    const sessions = await TenantSession.findActiveSessions(userId);

    const sessionData = sessions.map(session => ({
        id: session._id,
        device_info: session.device_info,
        location: session.location,
        login_time: session.login_time,
        last_activity: session.last_activity,
        expires_at: session.expires_at,
        is_current: req.cookies?.tenantRefreshToken === session.refresh_token
    }));

    logger.info('Retrieved tenant user sessions', { 
        userId, 
        projectId: req.user?.project_id,
        sessionCount: sessions.length 
    });

    const response = new ApiResponse(200, sessionData, "Sessions retrieved successfully");
    return res.status(response.statuscode).json(response);
});

/**
 * Revoke a specific tenant session
 */
const revokeTenantSession = asyncHandler(async (req, res) => {
    const { sessionId } = req.params;
    const userId = req.user?.id;

    ValidationHelper.validateObjectId(sessionId, 'Session ID');

    const session = await TenantSession.findOne({
        _id: sessionId,
        user_id: userId,
        status: 'active'
    });

    if (!session) {
        throw ApiError.notFound("Session not found");
    }

    session.status = 'revoked';
    session.logout_time = new Date();
    await session.save();

    logger.info('Tenant session revoked', { 
        sessionId, 
        userId,
        projectId: session.project_id
    });

    const response = new ApiResponse(200, null, "Session revoked successfully");
    return res.status(response.statuscode).json(response);
});

export {
    tenantRegister,
    tenantLogin,
    tenantLogout,
    getTenantSessions,
    revokeTenantSession
};