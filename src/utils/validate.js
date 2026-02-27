import { ApiError } from "./apierror.js";

class ValidationHelper {
    static validateRequired(fields, data) {
        const missingFields = [];
        
        for (const field of fields) {
            if (!data[field] || (typeof data[field] === 'string' && data[field].trim() === '')) {
                missingFields.push(field);
            }
        }
        
        if (missingFields.length > 0) {
            throw ApiError.badRequest(
                "Required fields are missing", 
                missingFields.map(field => `${field} is required`)
            );
        }
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw ApiError.badRequest("Invalid email format", ["Please provide a valid email address"]);
        }
    }

    static validatePassword(password) {
        if (password.length < 6) {
            throw ApiError.badRequest(
                "Password too weak", 
                ["Password must be at least 6 characters long"]
            );
        }
    }

    static validateStringLength(value, fieldName, minLength = 0, maxLength = Infinity) {
        if (typeof value !== 'string') {
            throw ApiError.badRequest(`${fieldName} must be a string`);
        }
        
        const trimmedValue = value.trim();
        
        if (trimmedValue.length < minLength) {
            throw ApiError.badRequest(
                `${fieldName} is too short`, 
                [`${fieldName} must be at least ${minLength} characters long`]
            );
        }
        
        if (trimmedValue.length > maxLength) {
            throw ApiError.badRequest(
                `${fieldName} is too long`, 
                [`${fieldName} must be no more than ${maxLength} characters long`]
            );
        }
        
        return trimmedValue;
    }

    static validateDate(dateString, fieldName) {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) {
            throw ApiError.badRequest(
                `Invalid ${fieldName}`, 
                [`${fieldName} must be a valid date`]
            );
        }
        return date;
    }

    static validateObjectId(id, fieldName = 'ID') {
        const objectIdRegex = /^[0-9a-fA-F]{24}$/;
        if (!objectIdRegex.test(id)) {
            throw ApiError.badRequest(
                `Invalid ${fieldName}`, 
                [`${fieldName} must be a valid MongoDB ObjectId`]
            );
        }
    }

    static sanitizeInput(input) {
        if (typeof input === 'string') {
            return input.trim().replace(/[<>]/g, ''); // Basic XSS prevention
        }
        return input;
    }
}

export { ValidationHelper };