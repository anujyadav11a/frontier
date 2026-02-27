import { ApiError } from '../utils/apierror.js';
import { logger } from '../utils/Logger.js';

export const errorHandler = (err, req, res, next) => {
    let error = err;

    // If it's not an ApiError, convert it
    if (!(error instanceof ApiError)) {
        const statusCode = error.statusCode || 500;
        const message = error.message || 'Internal Server Error';
        error = new ApiError(statusCode, message, [], err.stack);
    }

    // Log the error
    logger.error('Error handled by global error handler', {
        error: error.message,
        statusCode: error.statuscode,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        userId: req.user?.id || 'anonymous',
        body: req.method !== 'GET' ? req.body : undefined
    });

    // Send error response
    const response = {
        success: error.success,
        message: error.message,
        statuscode: error.statuscode,
        timestamp: error.timestamp,
        ...(error.errors.length > 0 && { errors: error.errors }),
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    };

    res.status(error.statuscode).json(response);
};

// Handle 404 errors
export const notFoundHandler = (req, res, next) => {
    const error = ApiError.notFound(`Route ${req.originalUrl} not found`);
    next(error);
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', {
        reason: reason.toString(),
        stack: reason.stack
    });
    // Don't exit the process in production
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
        error: error.message,
        stack: error.stack
    });
    process.exit(1);
});