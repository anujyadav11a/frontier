import { logger } from './Logger.js';

const asyncHandler = (requestHandler) => {
    return async (req, res, next) => {
        try {
            await Promise.resolve(requestHandler(req, res, next));
        } catch (error) {
            // Log the error with context
            logger.error('AsyncHandler caught error:', {
                error: error.message,
                stack: error.stack,
                url: req.url,
                method: req.method,
                userId: req.user?.id || 'anonymous',
                body: req.method !== 'GET' ? req.body : undefined
            });
            
            // Pass error to global error handler
            next(error);
        }
    };
};

export { asyncHandler };