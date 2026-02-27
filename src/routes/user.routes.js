import express from 'express';
import { 
    userRegister, 
    userLogin, 
    userLogout, 
    getUserSessions, 
    revokeSession 
} from '../controllers/User.controller.js';
import { authMiddleware } from '../middleware/auth.middleware.js'; // You'll need to create this

const userrouter = express.Router();

// Public routes
userrouter.route('/register').post(userRegister);
userrouter.route('/login').post(userLogin);

// Protected routes (require authentication)
userrouter.route('/logout').post(authMiddleware, userLogout);
export default userrouter;