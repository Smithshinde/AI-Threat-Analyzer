export class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code       = code;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(msg, code = 'BAD_REQUEST')    { return new AppError(msg, 400, code); }
  static unauthorized(msg = 'Unauthorized')         { return new AppError(msg, 401, 'UNAUTHORIZED'); }
  static forbidden(msg = 'Forbidden')               { return new AppError(msg, 403, 'FORBIDDEN'); }
  static notFound(msg = 'Resource not found')       { return new AppError(msg, 404, 'NOT_FOUND'); }
  static conflict(msg, code = 'CONFLICT')           { return new AppError(msg, 409, code); }
  static unprocessable(msg)                         { return new AppError(msg, 422, 'UNPROCESSABLE'); }
}
