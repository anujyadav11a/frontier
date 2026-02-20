import express from 'express';
import { 
    userRegister, 
    userLogin, 
    userLogout, 
    getUserSessions, 
    revokeSession 
} from '../controllers/User.controller.js';
import { authMiddleware } from '../middleware/auth.middleware.js'; // You'll need to create this

const router = express.Router();

// Public routes
router.post('/register', userRegister);
router.post('/login', userLogin);

// Protected routes (require authentication)
router.post('/logout', authMiddleware, userLogout);
router.get('/sessions', authMiddleware, getUserSessions);
router.delete('/sessions/:sessionId', authMiddleware, revokeSession);

export default router;