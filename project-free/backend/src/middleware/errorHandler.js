import logger from '../utils/logger.js';

export function errorHandler(err, req, res, _next) {
  // Validation errors from express-validator
  if (err.type === 'validation') {
    return res.status(422).json({ success: false, code: 'VALIDATION_ERROR', errors: err.errors });
  }

  const statusCode = err.statusCode || 500;
  const code       = err.code       || 'INTERNAL_ERROR';
  const message    = err.isOperational ? err.message : 'An unexpected error occurred';

  if (!err.isOperational) {
    logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  }

  return res.status(statusCode).json({ success: false, code, message });
}

export function notFoundHandler(req, res) {
  res.status(404).json({ success: false, code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` });
}
