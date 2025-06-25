import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../database/init.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { serviceValidation, commentValidation, idValidation, paginationValidation } from '../middleware/validation.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { auditLog } from '../utils/audit.js';

const router = express.Router();

// Get all services
router.get('/', authenticateToken, paginationValidation, asyncHandler(async (req, res) => {
  const db = getDatabase();
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  
  let whereClause = '';
  let params = [];
  
  // Non-admin users can only see services for their vehicles
  if (req.user.role !== 'admin') {
    whereClause = 'WHERE v.user_id = ?';
    params.push(req.user.id);
  }
  
  // Add status filter
  if (req.query.status) {
    const statusClause = whereClause ? ' AND ' : ' WHERE ';
    whereClause += `${statusClause}s.status = ?`;
    params.push(req.query.status);
  }
  
  const services = await db.allAsync(`
    SELECT s.*, v.plate_number, v.vehicle_type,
           u1.username as created_by_name,
           u2.username as assigned_to_name
    FROM services s
    JOIN vehicles v ON s.vehicle_id = v.id
    JOIN users u1 ON s.created_by = u1.id
    LEFT JOIN users u2 ON s.assigned_to = u2.id
    ${whereClause}
    ORDER BY s.created_at DESC
    LIMIT ? OFFSET ?
  `, [...params, limit, offset]);
  
  const countResult = await db.getAsync(`
    SELECT COUNT(*) as total
    FROM services s
    JOIN vehicles v ON s.vehicle_id = v.id
    ${whereClause}
  `, params);
  
  const total = countResult.total;
  const totalPages = Math.ceil(total / limit);
  
  res.json({
    services,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  });
}));

// Get service by ID
router.get('/:id', authenticateToken, idValidation, asyncHandler(async (req, res) => {
  const db = getDatabase();
  
  let whereClause = 'WHERE s.id = ?';
  let params = [req.params.id];
  
  // Non-admin users can only see services for their vehicles
  if (req.user.role !== 'admin') {
    whereClause += ' AND v.user_id = ?';
    params.push(req.user.id);
  }
  
  const service = await db.getAsync(`
    SELECT s.*, v.plate_number, v.vehicle_type,
           u1.username as created_by_name,
           u2.username as assigned_to_name
    FROM services s
    JOIN vehicles v ON s.vehicle_id = v.id
    JOIN users u1 ON s.created_by = u1.id
    LEFT JOIN users u2 ON s.assigned_to = u2.id
    ${whereClause}
  `, params);
  
  if (!service) {
    return res.status(404).json({ error: 'Service not found' });
  }
  
  // Get comments
  const comments = await db.allAsync(`
    SELECT c.*, u.username
    FROM service_comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.service_id = ?
    ORDER BY c.created_at ASC
  `, [req.params.id]);
  
  res.json({
    ...service,
    comments
  });
}));

// Create new service
router.post('/', authenticateToken, serviceValidation, asyncHandler(async (req, res) => {
  const { vehicle_id, service_type, priority, description, expected_date } = req.body;
  const db = getDatabase();
  
  // Check if vehicle exists and user has access
  let vehicleQuery = 'SELECT * FROM vehicles WHERE id = ?';
  let vehicleParams = [vehicle_id];
  
  if (req.user.role !== 'admin') {
    vehicleQuery += ' AND user_id = ?';
    vehicleParams.push(req.user.id);
  }
  
  const vehicle = await db.getAsync(vehicleQuery, vehicleParams);
  
  if (!vehicle) {
    return res.status(404).json({ error: 'Vehicle not found or access denied' });
  }
  
  const serviceId = uuidv4();
  
  await db.runAsync(
    'INSERT INTO services (id, vehicle_id, service_type, priority, description, expected_date, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [serviceId, vehicle_id, service_type, priority, description, expected_date, req.user.id]
  );
  
  const service = await db.getAsync(
    'SELECT * FROM services WHERE id = ?',
    [serviceId]
  );
  
  await auditLog(req.user.id, 'SERVICE_CREATED', 'service', serviceId, 
    `Created service for vehicle ${vehicle.plate_number}`, req.ip, req.get('User-Agent'));
  
  res.status(201).json(service);
}));

// Update service
router.put('/:id', authenticateToken, idValidation, asyncHandler(async (req, res) => {
  const { service_type, priority, description, expected_date, status, assigned_to } = req.body;
  const db = getDatabase();
  
  // Check if service exists and user has access
  let serviceQuery = `
    SELECT s.*, v.user_id as vehicle_owner
    FROM services s
    JOIN vehicles v ON s.vehicle_id = v.id
    WHERE s.id = ?
  `;
  let serviceParams = [req.params.id];
  
  if (req.user.role !== 'admin') {
    serviceQuery += ' AND (v.user_id = ? OR s.assigned_to = ?)';
    serviceParams.push(req.user.id, req.user.id);
  }
  
  const service = await db.getAsync(serviceQuery, serviceParams);
  
  if (!service) {
    return res.status(404).json({ error: 'Service not found or access denied' });
  }
  
  // Build update query dynamically
  const updates = [];
  const params = [];
  
  if (service_type) {
    updates.push('service_type = ?');
    params.push(service_type);
  }
  if (priority) {
    updates.push('priority = ?');
    params.push(priority);
  }
  if (description) {
    updates.push('description = ?');
    params.push(description);
  }
  if (expected_date) {
    updates.push('expected_date = ?');
    params.push(expected_date);
  }
  if (status) {
    updates.push('status = ?');
    params.push(status);
    
    if (status === 'completed') {
      updates.push('completed_date = CURRENT_TIMESTAMP');
    }
  }
  if (assigned_to && req.user.role === 'admin') {
    updates.push('assigned_to = ?');
    params.push(assigned_to);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }
  
  updates.push('updated_at = CURRENT_TIMESTAMP');
  params.push(req.params.id);
  
  await db.runAsync(
    `UPDATE services SET ${updates.join(', ')} WHERE id = ?`,
    params
  );
  
  const updatedService = await db.getAsync(
    'SELECT * FROM services WHERE id = ?',
    [req.params.id]
  );
  
  await auditLog(req.user.id, 'SERVICE_UPDATED', 'service', req.params.id, 
    `Updated service status to ${status || 'modified'}`, req.ip, req.get('User-Agent'));
  
  res.json(updatedService);
}));

// Add comment to service
router.post('/:id/comments', authenticateToken, idValidation, commentValidation, asyncHandler(async (req, res) => {
  const { comment } = req.body;
  const db = getDatabase();
  
  // Check if service exists and user has access
  let serviceQuery = `
    SELECT s.id
    FROM services s
    JOIN vehicles v ON s.vehicle_id = v.id
    WHERE s.id = ?
  `;
  let serviceParams = [req.params.id];
  
  if (req.user.role !== 'admin') {
    serviceQuery += ' AND (v.user_id = ? OR s.assigned_to = ?)';
    serviceParams.push(req.user.id, req.user.id);
  }
  
  const service = await db.getAsync(serviceQuery, serviceParams);
  
  if (!service) {
    return res.status(404).json({ error: 'Service not found or access denied' });
  }
  
  const commentId = uuidv4();
  
  await db.runAsync(
    'INSERT INTO service_comments (id, service_id, user_id, comment) VALUES (?, ?, ?, ?)',
    [commentId, req.params.id, req.user.id, comment]
  );
  
  const newComment = await db.getAsync(`
    SELECT c.*, u.username
    FROM service_comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.id = ?
  `, [commentId]);
  
  await auditLog(req.user.id, 'COMMENT_ADDED', 'service', req.params.id, 
    'Added comment to service', req.ip, req.get('User-Agent'));
  
  res.status(201).json(newComment);
}));

// Delete service (admin only)
router.delete('/:id', authenticateToken, requireRole('admin'), idValidation, asyncHandler(async (req, res) => {
  const db = getDatabase();
  
  const service = await db.getAsync(
    'SELECT * FROM services WHERE id = ?',
    [req.params.id]
  );
  
  if (!service) {
    return res.status(404).json({ error: 'Service not found' });
  }
  
  await db.runAsync(
    'DELETE FROM services WHERE id = ?',
    [req.params.id]
  );
  
  await auditLog(req.user.id, 'SERVICE_DELETED', 'service', req.params.id, 
    'Deleted service', req.ip, req.get('User-Agent'));
  
  res.json({ message: 'Service deleted successfully' });
}));

export default router;