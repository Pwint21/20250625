import { body, param, query, validationResult } from 'express-validator';

export const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

export const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long'),
  validateRequest
];

export const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least 8 characters with uppercase, lowercase, number, and special character'),
  validateRequest
];

export const vehicleValidation = [
  body('plate_number')
    .isLength({ min: 1, max: 20 })
    .matches(/^[A-Z0-9-]+$/)
    .withMessage('Plate number must contain only uppercase letters, numbers, and hyphens'),
  body('vehicle_type')
    .isIn(['truck', 'van', 'car', 'motorcycle'])
    .withMessage('Invalid vehicle type'),
  validateRequest
];

export const serviceValidation = [
  body('vehicle_id')
    .isUUID()
    .withMessage('Valid vehicle ID is required'),
  body('service_type')
    .isIn(['maintenance', 'repair', 'inspection', 'cleaning'])
    .withMessage('Invalid service type'),
  body('priority')
    .isIn(['low', 'medium', 'high', 'urgent'])
    .withMessage('Invalid priority level'),
  body('description')
    .isLength({ min: 10, max: 1000 })
    .withMessage('Description must be between 10 and 1000 characters'),
  body('expected_date')
    .optional()
    .isISO8601()
    .withMessage('Expected date must be a valid ISO 8601 date'),
  validateRequest
];

export const commentValidation = [
  body('comment')
    .isLength({ min: 1, max: 500 })
    .withMessage('Comment must be between 1 and 500 characters'),
  validateRequest
];

export const idValidation = [
  param('id')
    .isUUID()
    .withMessage('Valid ID is required'),
  validateRequest
];

export const paginationValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  validateRequest
];