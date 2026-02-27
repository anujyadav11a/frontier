import fs from 'fs';
import path from 'path';

class Logger {
    constructor() {
        this.logDir = path.join(process.cwd(), 'logs');
        this.ensureLogDirectory();
    }

    ensureLogDirectory() {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    formatMessage(level, message, meta = {}) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            message,
            ...meta
        };
        return JSON.stringify(logEntry) + '\n';
    }

    writeToFile(filename, content) {
        const filePath = path.join(this.logDir, filename);
        fs.appendFileSync(filePath, content);
    }

    error(message, meta = {}) {
        const logMessage = this.formatMessage('ERROR', message, meta);
        console.error(`🔴 [ERROR] ${message}`, meta);
        this.writeToFile('error.log', logMessage);
        this.writeToFile('combined.log', logMessage);
    }

    warn(message, meta = {}) {
        const logMessage = this.formatMessage('WARN', message, meta);
        console.warn(`🟡 [WARN] ${message}`, meta);
        this.writeToFile('combined.log', logMessage);
    }

    info(message, meta = {}) {
        const logMessage = this.formatMessage('INFO', message, meta);
        console.log(`🔵 [INFO] ${message}`, meta);
        this.writeToFile('combined.log', logMessage);
    }

    debug(message, meta = {}) {
        if (process.env.NODE_ENV === 'development') {
            const logMessage = this.formatMessage('DEBUG', message, meta);
            console.log(`🟢 [DEBUG] ${message}`, meta);
            this.writeToFile('debug.log', logMessage);
        }
    }

    logRequest(req, res, next) {
        const start = Date.now();
        
        res.on('finish', () => {
            const duration = Date.now() - start;
            const logData = {
                method: req.method,
                url: req.url,
                statusCode: res.statusCode,
                duration: `${duration}ms`,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            };

            if (res.statusCode >= 400) {
                this.error(`HTTP ${res.statusCode} - ${req.method} ${req.url}`, logData);
            } else {
                this.info(`HTTP ${res.statusCode} - ${req.method} ${req.url}`, logData);
            }
        });

        next();
    }
}

const logger = new Logger();

export { logger };