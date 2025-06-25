import { getDatabase } from '../database/init.js';
import { v4 as uuidv4 } from 'uuid';

export const auditLog = async (userId, action, resourceType, resourceId, details, ipAddress, userAgent) => {
  try {
    const db = getDatabase();
    const auditId = uuidv4();
    
    await db.runAsync(
      'INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [auditId, userId, action, resourceType, resourceId, details, ipAddress, userAgent]
    );
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
};