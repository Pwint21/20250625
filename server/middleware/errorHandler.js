export const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  // Default error
  let error = {
    message: 'Internal server error',
    status: 500
  };
  
  // Validation errors
  if (err.name === 'ValidationError') {
    error.message = 'Validation failed';
    error.status = 400;
    error.details = err.details;
  }
  
  // Database constraint errors
  if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
    error.message = 'Resource already exists';
    error.status = 409;
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error.message = 'Invalid token';
    error.status = 401;
  }
  
  if (err.name === 'TokenExpiredError') {
    error.message = 'Token expired';
    error.status = 401;
  }
  
  // Custom errors
  if (err.status) {
    error.status = err.status;
    error.message = err.message;
  }
  
  res.status(error.status).json({
    error: error.message,
    ...(error.details && { details: error.details }),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

export const notFound = (req, res) => {
  res.status(404).json({ error: 'Resource not found' });
};

export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};