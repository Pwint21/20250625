import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../database/init.js';
import { loginValidation, registerValidation } from '../middleware/validation.js';
import { authenticateToken } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { auditLog } from '../utils/audit.js';

const router = express.Router();

// Login
router.post('/login', loginValidation, asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const db = getDatabase();
  
  // Get user with password hash
  const user = await db.getAsync(
    'SELECT * FROM users WHERE email = ? AND is_active = 1',
    [email]
  );
  
  if (!user) {
    await auditLog(null, 'LOGIN_FAILED', 'auth', null, 
      `Failed login attempt for email: ${email}`, req.ip, req.get('User-Agent'));
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Check if account is locked
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(423).json({ error: 'Account temporarily locked due to too many failed attempts' });
  }
  
  // Verify password
  const isValidPassword = await bcrypt.compare(password, user.password_hash);
  
  if (!isValidPassword) {
    // Increment failed attempts
    const failedAttempts = (user.failed_login_attempts || 0) + 1;
    let lockedUntil = null;
    
    if (failedAttempts >= 5) {
      lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
    }
    
    await db.runAsync(
      'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
      [failedAttempts, lockedUntil, user.id]
    );
    
    await auditLog(user.id, 'LOGIN_FAILED', 'auth', null, 
      `Failed login attempt`, req.ip, req.get('User-Agent'));
    
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Reset failed attempts on successful login
  await db.runAsync(
    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?',
    [user.id]
  );
  
  // Create JWT token
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
  
  // Store session
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  await db.runAsync(
    'INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)',
    [sessionId, user.id, token, expiresAt]
  );
  
  await auditLog(user.id, 'LOGIN_SUCCESS', 'auth', null, 
    'User logged in successfully', req.ip, req.get('User-Agent'));
  
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    }
  });
}));

// Register
router.post('/register', registerValidation, asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  const db = getDatabase();
  
  // Check if user already exists
  const existingUser = await db.getAsync(
    'SELECT id FROM users WHERE email = ? OR username = ?',
    [email, username]
  );
  
  if (existingUser) {
    return res.status(409).json({ error: 'User already exists' });
  }
  
  // Hash password
  const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  
  // Create user
  const userId = uuidv4();
  await db.runAsync(
    'INSERT INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
    [userId, username, email, passwordHash, 'user']
  );
  
  await auditLog(userId, 'USER_REGISTERED', 'user', userId, 
    'New user registered', req.ip, req.get('User-Agent'));
  
  res.status(201).json({
    message: 'User registered successfully',
    user: {
      id: userId,
      username,
      email,
      role: 'user'
    }
  });
}));

// Logout
router.post('/logout', authenticateToken, asyncHandler(async (req, res) => {
  const db = getDatabase();
  
  // Remove session
  await db.runAsync(
    'DELETE FROM sessions WHERE user_id = ?',
    [req.user.id]
  );
  
  await auditLog(req.user.id, 'LOGOUT', 'auth', null, 
    'User logged out', req.ip, req.get('User-Agent'));
  
  res.json({ message: 'Logged out successfully' });
}));

// Get current user
router.get('/me', authenticateToken, asyncHandler(async (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    }
  });
}));

// Change password
router.put('/change-password', authenticateToken, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const db = getDatabase();
  
  // Validate new password
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long' });
  }
  
  // Get current user with password
  const user = await db.getAsync(
    'SELECT password_hash FROM users WHERE id = ?',
    [req.user.id]
  );
  
  // Verify current password
  const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
  if (!isValidPassword) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  
  // Hash new password
  const newPasswordHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  
  // Update password
  await db.runAsync(
    'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [newPasswordHash, req.user.id]
  );
  
  // Invalidate all sessions
  await db.runAsync(
    'DELETE FROM sessions WHERE user_id = ?',
    [req.user.id]
  );
  
  await auditLog(req.user.id, 'PASSWORD_CHANGED', 'user', req.user.id, 
    'Password changed successfully', req.ip, req.get('User-Agent'));
  
  res.json({ message: 'Password changed successfully. Please log in again.' });
}));

export default router;