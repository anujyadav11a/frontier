// Simple in-memory session store (for development only)
// In production, use Redis or a proper session store

const sessions = new Map();

export const sessionMiddleware = (req, res, next) => {
    const sessionId = req.cookies.sessionId || generateSessionId();
    
    if (!req.cookies.sessionId) {
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
    }
    
    // Get or create session
    if (!sessions.has(sessionId)) {
        sessions.set(sessionId, {});
    }
    
    req.session = sessions.get(sessionId);
    req.sessionId = sessionId;
    
    next();
};

function generateSessionId() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// Cleanup expired sessions periodically
setInterval(() => {
    // Simple cleanup - in production use proper session management
    if (sessions.size > 1000) {
        const entries = Array.from(sessions.entries());
        const toDelete = entries.slice(0, entries.length - 500);
        toDelete.forEach(([key]) => sessions.delete(key));
    }
}, 60 * 60 * 1000); // Every hour