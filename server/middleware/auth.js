import jwt from 'jsonwebtoken';
import { getDatabase } from '../database/init.js';

export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const db = getDatabase();
    
    // Check if session exists and is valid
    const session = await db.getAsync(
      'SELECT * FROM sessions WHERE user_id = ? AND expires_at > DATETIME("now")',
      [decoded.userId]
    );
    
    if (!session) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
    
    // Get user details
    const user = await db.getAsync(
      'SELECT id, username, email, role, is_active FROM users WHERE id = ? AND is_active = 1',
      [decoded.userId]
    );
    
    if (!user) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(500).json({ error: 'Authentication error' });
  }
};

export const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const userRoles = Array.isArray(roles) ? roles : [roles];
    if (!userRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

export const requireOwnershipOrAdmin = async (req, res, next) => {
  try {
    const { id } = req.params;
    const db = getDatabase();
    
    if (req.user.role === 'admin') {
      return next();
    }
    
    // Check if user owns the resource
    const resource = await db.getAsync(
      'SELECT user_id FROM vehicles WHERE id = ?',
      [id]
    );
    
    if (!resource || resource.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    next();
  } catch (error) {
    return res.status(500).json({ error: 'Authorization error' });
  }
};