import Router from 'express';
import { googleOAuthController } from '../controllers/googleOAuth.controller.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const Googlerouter = Router();

// Google OAuth routes
Googlerouter.get('/google', asyncHandler(googleOAuthController.redirectToGoogle.bind(googleOAuthController)));
Googlerouter.get('/google/callback', asyncHandler(googleOAuthController.handleCallback.bind(googleOAuthController)));

// Protected routes (add auth middleware as needed)
Googlerouter.post('/google/refresh/:identityId', asyncHandler(googleOAuthController.refreshAccessToken.bind(googleOAuthController)));
Googlerouter.post('/google/revoke/:identityId', asyncHandler(googleOAuthController.revokeAccess.bind(googleOAuthController)));

export default Googlerouter;