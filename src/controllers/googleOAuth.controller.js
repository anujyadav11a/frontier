import axios from 'axios';
import { Identity } from '../models/Auth/console/identity.model.js';
import { User } from '../models/Auth/console/user.model.js';
import { ConsoleSession } from '../models/Auth/console/consoleSession.js';
import crypto from 'crypto';
import { ApiError } from '../utils/apierror.js';
import { ApiResponse } from '../utils/apiresponse.js';
import { logger } from '../utils/Logger.js';
import { ValidationHelper } from '../utils/validate.js';

export class GoogleOAuthController {
    constructor() {
        this.clientId = process.env.GOOGLE_CLIENT_ID;
        this.clientSecret = process.env.GOOGLE_CLIENT_SECRET;
        this.redirectUri = process.env.GOOGLE_REDIRECT_URI;
        this.tokenEndpoint = 'https://oauth2.googleapis.com/token';
        this.userInfoEndpoint = 'https://www.googleapis.com/oauth2/v2/userinfo';
        this.authEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    /**
     * Generate Google OAuth authorization URL and redirect
     */
    redirectToGoogle = asyncHandler(async (req, res) => {
        logger.info('Initiating Google OAuth flow', { 
            ip: req.ip, 
            userAgent: req.headers['user-agent'] 
        });

        // Validate environment variables
        if (!this.clientId || !this.clientSecret || !this.redirectUri) {
            logger.error('Missing Google OAuth configuration', {
                hasClientId: !!this.clientId,
                hasClientSecret: !!this.clientSecret,
                hasRedirectUri: !!this.redirectUri
            });
            throw ApiError.internal('OAuth configuration is incomplete');
        }

        // Generate state parameter for CSRF protection
        const state = crypto.randomBytes(32).toString('hex');
        
        // Store state in session
        req.session = req.session || {};
        req.session.oauthState = state;

        const scope = [
            'openid',
            'profile', 
            'email'
        ].join(' ');

        const authUrl = new URL(this.authEndpoint);
        authUrl.searchParams.append('client_id', this.clientId);
        authUrl.searchParams.append('redirect_uri', this.redirectUri);
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('scope', scope);
        authUrl.searchParams.append('state', state);
        authUrl.searchParams.append('access_type', 'offline');
        authUrl.searchParams.append('prompt', 'consent');

        logger.info('Generated OAuth URL successfully', { state });

        const response = new ApiResponse(
            200,
            {
                authUrl: authUrl.toString(),
                state: state
            },
            'OAuth URL generated successfully'
        );

        res.status(response.statuscode).json(response);
    });

    /**
     * Handle Google OAuth callback
     */
    handleCallback = asyncHandler(async (req, res) => {
        const { code, state, error } = req.query;

        logger.info('Handling OAuth callback', { 
            hasCode: !!code, 
            hasState: !!state, 
            hasError: !!error,
            ip: req.ip 
        });

        // Check for OAuth errors
        if (error) {
            logger.error('OAuth authorization failed', { error });
            throw ApiError.badRequest('OAuth authorization failed', [error]);
        }

        // Validate required parameters
        ValidationHelper.validateRequired(['code'], { code });

        // Validate state parameter (CSRF protection)
        if (!state || !req.session?.oauthState || state !== req.session.oauthState) {
            logger.error('CSRF validation failed', { 
                providedState: state, 
                sessionState: req.session?.oauthState 
            });
            throw ApiError.badRequest('Invalid state parameter - CSRF protection failed');
        }

        // Clear the state from session
        delete req.session.oauthState;

        // Exchange code for tokens
        const tokenData = await this.exchangeCodeForTokens(code);
        
        // Get user info from Google
        const userInfo = await this.getUserInfo(tokenData.access_token);

        // Process the OAuth authentication
        const result = await this.processOAuthUser(userInfo, tokenData, req);

        logger.info('OAuth authentication successful', { 
            userId: result.user.id, 
            email: result.user.email 
        });

        const response = new ApiResponse(
            200,
            result,
            'Google OAuth authentication successful'
        );

        res.status(response.statuscode).json(response);
    });

    /**
     * Exchange authorization code for access and refresh tokens
     */
    async exchangeCodeForTokens(code) {
        logger.debug('Exchanging authorization code for tokens');

        try {
            const response = await axios.post(this.tokenEndpoint, {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: this.redirectUri
            }, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });

            const tokenData = response.data;
            
            if (!tokenData.access_token) {
                logger.error('No access token received from Google', { tokenData });
                throw ApiError.badGateway('No access token received from Google');
            }

            logger.info('Successfully exchanged code for tokens', {
                hasAccessToken: !!tokenData.access_token,
                hasRefreshToken: !!tokenData.refresh_token,
                expiresIn: tokenData.expires_in
            });

            return {
                access_token: tokenData.access_token,
                refresh_token: tokenData.refresh_token,
                expires_in: tokenData.expires_in,
                token_type: tokenData.token_type || 'Bearer',
                scope: tokenData.scope,
                id_token: tokenData.id_token
            };

        } catch (error) {
            if (error.response) {
                logger.error('Google token exchange failed', {
                    status: error.response.status,
                    data: error.response.data
                });
                throw ApiError.badGateway(
                    `Failed to exchange code for tokens: ${error.response.data?.error_description || error.response.data?.error || 'Unknown error'}`
                );
            }
            
            logger.error('Token exchange network error', { error: error.message });
            throw ApiError.serviceUnavailable('Failed to connect to Google OAuth service');
        }
    }

    /**
     * Get user information from Google
     */
    async getUserInfo(accessToken) {
        logger.debug('Fetching user info from Google');

        try {
            const response = await axios.get(this.userInfoEndpoint, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`
                }
            });

            const userInfo = response.data;
            
            // Validate required user info
            if (!userInfo.id || !userInfo.email) {
                logger.error('Incomplete user info from Google', { userInfo });
                throw ApiError.badGateway('Incomplete user information received from Google');
            }

            // Validate email format
            ValidationHelper.validateEmail(userInfo.email);

            logger.info('Successfully retrieved user info', {
                userId: userInfo.id,
                email: userInfo.email,
                hasName: !!userInfo.name
            });

            return response.data;
        } catch (error) {
            if (error instanceof ApiError) {
                throw error; // Re-throw validation errors
            }

            if (error.response?.status === 401) {
                logger.error('Invalid access token for user info', { status: error.response.status });
                throw ApiError.unauthorized('Invalid or expired access token');
            }

            logger.error('Failed to get user info from Google', {
                status: error.response?.status,
                message: error.message
            });
            throw ApiError.serviceUnavailable('Failed to retrieve user information from Google');
        }
    }

    /**
     * Process OAuth user - create/update user and identity
     */
    async processOAuthUser(userInfo, tokenData, req) {
        const googleUserId = ValidationHelper.sanitizeInput(userInfo.id);
        const email = ValidationHelper.sanitizeInput(userInfo.email);
        const name = ValidationHelper.sanitizeInput(userInfo.name || email.split('@')[0]);
        const picture = userInfo.picture;

        logger.info('Processing OAuth user', { googleUserId, email, name: !!name });

        try {
            // Check if identity already exists
            let identity = await Identity.findByProvider('google', googleUserId);
            let user;

            if (identity) {
                logger.info('Existing identity found, updating', { identityId: identity._id });
                
                // Update existing identity
                await identity.updateTokenData({
                    refresh_token: tokenData.refresh_token,
                    expires_in: tokenData.expires_in,
                    scope: tokenData.scope?.split(' ')
                });

                // Update provider info
                identity.provider_email = email;
                identity.provider_name = name;
                if (picture) identity.provider_data.set('avatar', picture);
                await identity.save();

                // Get associated user
                user = await User.findById(identity.user_id);
                if (!user) {
                    logger.error('User not found for existing identity', { 
                        identityId: identity._id, 
                        userId: identity.user_id 
                    });
                    throw ApiError.internal('User account not found for existing OAuth identity');
                }
            } else {
                logger.info('New identity, checking for existing user', { email });
                
                // Check if user exists with same email
                user = await User.findOne({ email: email });

                if (!user) {
                    logger.info('Creating new user', { email, name });
                    
                    // Validate user data
                    ValidationHelper.validateStringLength(name, 'name', 1, 100);
                    ValidationHelper.validateEmail(email);
                    
                    // Create new user
                    user = new User({
                        name: name,
                        email: email,
                        password: this.generateRandomPassword(),
                        role: 'user'
                    });
                    await user.save();
                    
                    logger.info('New user created', { userId: user._id, email });
                } else {
                    logger.info('Linking OAuth to existing user', { userId: user._id, email });
                }

                // Create new identity
                identity = new Identity({
                    user_id: user._id,
                    provider: 'google',
                    provider_id: googleUserId,
                    provider_email: email,
                    provider_name: name,
                    refresh_token: tokenData.refresh_token,
                    expires_at: tokenData.expires_in ? 
                        new Date(Date.now() + (tokenData.expires_in * 1000)) : null,
                    scope: tokenData.scope ? tokenData.scope.split(' ') : [],
                    is_active: true
                });

                if (picture) {
                    identity.provider_data.set('avatar', picture);
                }

                await identity.save();
                logger.info('New identity created', { identityId: identity._id });

                // Set as primary if it's the user's first OAuth identity
                const userIdentities = await Identity.findByUser(user._id);
                if (userIdentities.length === 1) {
                    await Identity.setPrimaryIdentity(user._id, identity._id);
                    identity.is_primary = true;
                    logger.info('Set as primary identity', { identityId: identity._id });
                }
            }

            // Create session
            const session = await this.createSession(user, req);

            // Generate JWT tokens
            const accessToken = user.generateAccessToken();
            const refreshToken = user.generateRefreshToken();

            // Update user refresh token
            user.refreshtoken = refreshToken;
            await user.save();

            logger.info('OAuth user processing completed', { 
                userId: user._id, 
                sessionId: session._id 
            });

            return {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                tokens: {
                    accessToken,
                    refreshToken
                },
                session: {
                    id: session._id,
                    expires_at: session.expires_at
                },
                oauth: {
                    provider: 'google',
                    provider_id: googleUserId,
                    provider_email: email,
                    is_primary: identity.is_primary,
                    connected_at: identity.createdAt
                }
            };

        } catch (error) {
            if (error instanceof ApiError) {
                throw error; // Re-throw API errors
            }
            
            logger.error('Failed to process OAuth user', {
                error: error.message,
                stack: error.stack,
                googleUserId,
                email
            });
            throw ApiError.internal(`Failed to process OAuth user: ${error.message}`);
        }
    }

    /**
     * Create user session
     */
    async createSession(user, req) {
        try {
            const sessionToken = crypto.randomBytes(32).toString('hex');
            const refreshToken = crypto.randomBytes(32).toString('hex');

            const session = new ConsoleSession({
                user_id: user._id,
                session_token: sessionToken,
                refresh_token: refreshToken,
                ip_address: req.ip || req.connection.remoteAddress,
                user_agent: req.headers['user-agent'] || 'Unknown',
                expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                login_method: 'oauth'
            });

            const savedSession = await session.save();
            logger.info('Session created successfully', { 
                sessionId: savedSession._id, 
                userId: user._id 
            });
            
            return savedSession;
        } catch (error) {
            logger.error('Failed to create session', {
                error: error.message,
                userId: user._id
            });
            throw ApiError.internal(`Failed to create session: ${error.message}`);
        }
    }

    /**
     * Generate random password for OAuth users
     */
    generateRandomPassword() {
        return crypto.randomBytes(16).toString('hex');
    }

    /**
     * Refresh Google access token using refresh token
     */
    refreshAccessToken = asyncHandler(async (req, res) => {
        const { identityId } = req.params;
        
        // Validate identity ID
        ValidationHelper.validateObjectId(identityId, 'Identity ID');

        logger.info('Refreshing access token', { identityId });

        const identity = await Identity.findById(identityId);
        if (!identity || !identity.isRefreshTokenValid()) {
            logger.error('Invalid or expired refresh token', { identityId });
            throw ApiError.badRequest('Invalid or expired refresh token');
        }

        try {
            const response = await axios.post(this.tokenEndpoint, {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                refresh_token: identity.refresh_token,
                grant_type: 'refresh_token'
            }, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });

            const tokenData = response.data;
            
            // Update identity with new token data
            await identity.updateTokenData({
                refresh_token: tokenData.refresh_token || identity.refresh_token,
                expires_in: tokenData.expires_in,
                scope: tokenData.scope
            });

            logger.info('Access token refreshed successfully', { identityId });

            const apiResponse = new ApiResponse(
                200,
                {
                    access_token: tokenData.access_token,
                    expires_in: tokenData.expires_in,
                    token_type: tokenData.token_type
                },
                'Access token refreshed successfully'
            );

            res.status(apiResponse.statuscode).json(apiResponse);

        } catch (error) {
            if (error.response) {
                logger.error('Google token refresh failed', {
                    identityId,
                    status: error.response.status,
                    data: error.response.data
                });
                throw ApiError.badGateway(`Failed to refresh access token: ${error.response.data?.error_description || 'Unknown error'}`);
            }
            
            logger.error('Token refresh network error', { identityId, error: error.message });
            throw ApiError.serviceUnavailable('Failed to connect to Google OAuth service');
        }
    });

    /**
     * Revoke Google OAuth access
     */
    revokeAccess = asyncHandler(async (req, res) => {
        const { identityId } = req.params;
        
        // Validate identity ID
        ValidationHelper.validateObjectId(identityId, 'Identity ID');

        logger.info('Revoking OAuth access', { identityId });

        const identity = await Identity.findById(identityId);
        if (!identity) {
            logger.error('Identity not found for revocation', { identityId });
            throw ApiError.notFound('OAuth identity not found');
        }

        try {
            // Get current access token
            const tokenInfo = await this.refreshAccessToken(identityId);
            
            // Revoke at Google
            try {
                await axios.post('https://oauth2.googleapis.com/revoke', {
                    token: tokenInfo.access_token
                });
                logger.info('Successfully revoked token at Google', { identityId });
            } catch (revokeError) {
                logger.warn('Failed to revoke at Google (continuing with local revocation)', {
                    identityId,
                    error: revokeError.message
                });
            }

            // Revoke locally
            await identity.revoke();
            logger.info('OAuth access revoked successfully', { identityId });

            const apiResponse = new ApiResponse(
                200,
                null,
                'OAuth access revoked successfully'
            );

            res.status(apiResponse.statuscode).json(apiResponse);

        } catch (error) {
            if (error instanceof ApiError) {
                throw error;
            }
            
            logger.error('Failed to revoke OAuth access', {
                identityId,
                error: error.message
            });
            throw ApiError.internal(`Failed to revoke access: ${error.message}`);
        }
    });
}

export const googleOAuthController = new GoogleOAuthController();