import express from 'express';
import { googleOAuthController } from '../controllers/googleOAuth.controller.js';
import { asyncHandler } from '../utils/asynchandler.js';

const router = express.Router();

// Google OAuth routes
router.get('/google', googleOAuthController.redirectToGoogle);
router.get('/google/callback', googleOAuthController.handleCallback);

// Protected routes (add auth middleware as needed)
router.post('/google/refresh/:identityId', googleOAuthController.refreshAccessToken);
router.post('/google/revoke/:identityId', googleOAuthController.revokeAccess);

export default router;