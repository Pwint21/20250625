import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../database/init.js';
import { authenticateToken, requireRole, requireOwnershipOrAdmin } from '../middleware/auth.js';
import { vehicleValidation, idValidation, paginationValidation } from '../middleware/validation.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { auditLog } from '../utils/audit.js';

const router = express.Router();

// Get all vehicles (with pagination and filtering)
router.get('/', authenticateToken, paginationValidation, asyncHandler(async (req, res) => {
  const db = getDatabase();
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  
  let whereClause = '';
  let params = [];
  
  // Non-admin users can only see their own vehicles
  if (req.user.role !== 'admin') {
    whereClause = 'WHERE v.user_id = ?';
    params.push(req.user.id);
  }
  
  // Add search filter
  if (req.query.search) {
    const searchClause = whereClause ? ' AND ' : ' WHERE ';
    whereClause += `${searchClause}(v.plate_number LIKE ? OR v.vehicle_type LIKE ?)`;
    params.push(`%${req.query.search}%`, `%${req.query.search}%`);
  }
  
  // Get vehicles with user information
  const vehicles = await db.allAsync(`
    SELECT v.*, u.username, u.email
    FROM vehicles v
    JOIN users u ON v.user_id = u.id
    ${whereClause}
    ORDER BY v.created_at DESC
    LIMIT ? OFFSET ?
  `, [...params, limit, offset]);
  
  // Get total count
  const countResult = await db.getAsync(`
    SELECT COUNT(*) as total
    FROM vehicles v
    JOIN users u ON v.user_id = u.id
    ${whereClause}
  `, params);
  
  const total = countResult.total;
  const totalPages = Math.ceil(total / limit);
  
  res.json({
    vehicles,
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

// Get vehicle by ID
router.get('/:id', authenticateToken, idValidation, requireOwnershipOrAdmin, asyncHandler(async (req, res) => {
  const db = getDatabase();
  
  const vehicle = await db.getAsync(`
    SELECT v.*, u.username, u.email
    FROM vehicles v
    JOIN users u ON v.user_id = u.id
    WHERE v.id = ?
  `, [req.params.id]);
  
  if (!vehicle) {
    return res.status(404).json({ error: 'Vehicle not found' });
  }
  
  res.json(vehicle);
}));

// Create new vehicle
router.post('/', authenticateToken, vehicleValidation, asyncHandler(async (req, res) => {
  const { plate_number, vehicle_type } = req.body;
  const db = getDatabase();
  
  // Check if plate number already exists
  const existingVehicle = await db.getAsync(
    'SELECT id FROM vehicles WHERE plate_number = ?',
    [plate_number]
  );
  
  if (existingVehicle) {
    return res.status(409).json({ error: 'Vehicle with this plate number already exists' });
  }
  
  const vehicleId = uuidv4();
  const userId = req.user.role === 'admin' && req.body.user_id ? req.body.user_id : req.user.id;
  
  await db.runAsync(
    'INSERT INTO vehicles (id, plate_number, vehicle_type, user_id) VALUES (?, ?, ?, ?)',
    [vehicleId, plate_number, vehicle_type, userId]
  );
  
  const vehicle = await db.getAsync(
    'SELECT * FROM vehicles WHERE id = ?',
    [vehicleId]
  );
  
  await auditLog(req.user.id, 'VEHICLE_CREATED', 'vehicle', vehicleId, 
    `Created vehicle ${plate_number}`, req.ip, req.get('User-Agent'));
  
  res.status(201).json(vehicle);
}));

// Update vehicle
router.put('/:id', authenticateToken, idValidation, vehicleValidation, requireOwnershipOrAdmin, asyncHandler(async (req, res) => {
  const { plate_number, vehicle_type, status } = req.body;
  const db = getDatabase();
  
  // Check if vehicle exists
  const existingVehicle = await db.getAsync(
    'SELECT * FROM vehicles WHERE id = ?',
    [req.params.id]
  );
  
  if (!existingVehicle) {
    return res.status(404).json({ error: 'Vehicle not found' });
  }
  
  // Check if new plate number conflicts with existing vehicle
  if (plate_number !== existingVehicle.plate_number) {
    const plateConflict = await db.getAsync(
      'SELECT id FROM vehicles WHERE plate_number = ? AND id != ?',
      [plate_number, req.params.id]
    );
    
    if (plateConflict) {
      return res.status(409).json({ error: 'Vehicle with this plate number already exists' });
    }
  }
  
  await db.runAsync(
    'UPDATE vehicles SET plate_number = ?, vehicle_type = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [plate_number, vehicle_type, status || existingVehicle.status, req.params.id]
  );
  
  const updatedVehicle = await db.getAsync(
    'SELECT * FROM vehicles WHERE id = ?',
    [req.params.id]
  );
  
  await auditLog(req.user.id, 'VEHICLE_UPDATED', 'vehicle', req.params.id, 
    `Updated vehicle ${plate_number}`, req.ip, req.get('User-Agent'));
  
  res.json(updatedVehicle);
}));

// Delete vehicle
router.delete('/:id', authenticateToken, idValidation, requireOwnershipOrAdmin, asyncHandler(async (req, res) => {
  const db = getDatabase();
  
  const vehicle = await db.getAsync(
    'SELECT * FROM vehicles WHERE id = ?',
    [req.params.id]
  );
  
  if (!vehicle) {
    return res.status(404).json({ error: 'Vehicle not found' });
  }
  
  await db.runAsync(
    'DELETE FROM vehicles WHERE id = ?',
    [req.params.id]
  );
  
  await auditLog(req.user.id, 'VEHICLE_DELETED', 'vehicle', req.params.id, 
    `Deleted vehicle ${vehicle.plate_number}`, req.ip, req.get('User-Agent'));
  
  res.json({ message: 'Vehicle deleted successfully' });
}));

export default router;