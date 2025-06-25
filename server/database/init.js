import sqlite3 from 'sqlite3';
import { promisify } from 'util';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdir } from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let db;

export const initDatabase = async () => {
  try {
    // Ensure database directory exists
    const dbDir = join(__dirname, '../../database');
    await mkdir(dbDir, { recursive: true });
    
    const dbPath = process.env.DB_PATH || join(dbDir, 'fleet.db');
    
    db = new sqlite3.Database(dbPath);
    
    // Promisify database methods
    db.runAsync = promisify(db.run.bind(db));
    db.getAsync = promisify(db.get.bind(db));
    db.allAsync = promisify(db.all.bind(db));
    
    await createTables();
    await seedDefaultData();
    
    console.log('Database initialized successfully');
    return db;
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
};

const createTables = async () => {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until DATETIME
    )`,
    
    `CREATE TABLE IF NOT EXISTS vehicles (
      id TEXT PRIMARY KEY,
      plate_number TEXT UNIQUE NOT NULL,
      vehicle_type TEXT NOT NULL,
      user_id TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`,
    
    `CREATE TABLE IF NOT EXISTS services (
      id TEXT PRIMARY KEY,
      vehicle_id TEXT NOT NULL,
      service_type TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'open',
      description TEXT,
      assigned_to TEXT,
      created_by TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expected_date DATETIME,
      completed_date DATETIME,
      FOREIGN KEY (vehicle_id) REFERENCES vehicles (id) ON DELETE CASCADE,
      FOREIGN KEY (created_by) REFERENCES users (id),
      FOREIGN KEY (assigned_to) REFERENCES users (id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS service_comments (
      id TEXT PRIMARY KEY,
      service_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      comment TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`
  ];
  
  for (const table of tables) {
    await db.runAsync(table);
  }
  
  // Create indexes for better performance
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)',
    'CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)',
    'CREATE INDEX IF NOT EXISTS idx_vehicles_plate ON vehicles (plate_number)',
    'CREATE INDEX IF NOT EXISTS idx_vehicles_user ON vehicles (user_id)',
    'CREATE INDEX IF NOT EXISTS idx_services_vehicle ON services (vehicle_id)',
    'CREATE INDEX IF NOT EXISTS idx_services_status ON services (status)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at)',
    'CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)',
    'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at)'
  ];
  
  for (const index of indexes) {
    await db.runAsync(index);
  }
};

const seedDefaultData = async () => {
  // Check if admin user exists
  const adminExists = await db.getAsync('SELECT id FROM users WHERE role = "admin" LIMIT 1');
  
  if (!adminExists) {
    const adminId = uuidv4();
    const hashedPassword = await bcrypt.hash('Admin@123!', 12);
    
    await db.runAsync(
      `INSERT INTO users (id, username, email, password_hash, role) 
       VALUES (?, ?, ?, ?, ?)`,
      [adminId, 'admin', 'admin@fleet.com', hashedPassword, 'admin']
    );
    
    console.log('Default admin user created: admin@fleet.com / Admin@123!');
  }
};

export const getDatabase = () => {
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db;
};

export const closeDatabase = () => {
  if (db) {
    db.close();
  }
};