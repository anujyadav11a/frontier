class ApiError extends Error {
    constructor(
        statuscode,
        message = "Something went wrong",
        errors = [],
        stack = "",
        isOperational = true
    ) {
        super(message);
        this.statuscode = statuscode;
        this.data = null;
        this.message = message;
        this.success = false;
        this.errors = errors;
        this.isOperational = isOperational; // Distinguish operational vs programming errors
        this.timestamp = new Date().toISOString();

        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }

    // Static methods for common error types
    static badRequest(message = "Bad Request", errors = []) {
        return new ApiError(400, message, errors);
    }

    static unauthorized(message = "Unauthorized", errors = []) {
        return new ApiError(401, message, errors);
    }

    static forbidden(message = "Forbidden", errors = []) {
        return new ApiError(403, message, errors);
    }

    static notFound(message = "Not Found", errors = []) {
        return new ApiError(404, message, errors);
    }

    static conflict(message = "Conflict", errors = []) {
        return new ApiError(409, message, errors);
    }

    static unprocessableEntity(message = "Unprocessable Entity", errors = []) {
        return new ApiError(422, message, errors);
    }

    static tooManyRequests(message = "Too Many Requests", errors = []) {
        return new ApiError(429, message, errors);
    }

    static internal(message = "Internal Server Error", errors = []) {
        return new ApiError(500, message, errors);
    }

    static badGateway(message = "Bad Gateway", errors = []) {
        return new ApiError(502, message, errors);
    }

    static serviceUnavailable(message = "Service Unavailable", errors = []) {
        return new ApiError(503, message, errors);
    }
}

export { ApiError }