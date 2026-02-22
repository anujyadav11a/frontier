import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser'; 
import googleOAuthRoutes from './routes/googleOAuth.routes.js';
import userRoutes from './routes/user.routes.js';
import { authMiddleware } from './middleware/auth.middleware.js';

import { logger } from './utils/Logger.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.middleware.js';
import { refreshTokenMiddleware } from './middleware/auth.middleware.js';

const app = express();

const Options={
    origin:process.env.CORS_ORIGIN,
    Credential:true
}

// Request logging middleware
app.use(logger.logRequest.bind(logger));

app.use(cors(Options))
app.use(express.json({limit:"10kb"}))
app.use(express.urlencoded({limit:"10kb"}))
app.use(express.static("public"))
app.use(cookieParser())
app.use(authMiddleware)
app.use(refreshTokenMiddleware) // Auto-refresh tokens



// Routes
app.use('/auth', googleOAuthRoutes);
app.use('/api/v1/users', userRoutes);

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

export default app