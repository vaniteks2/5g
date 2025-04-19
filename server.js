// server.js - Main API server file
const express = require('express');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');

// Load environment variables - only load from .env file in development
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
}

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// JWT token secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware for authentication
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const deviceId = req.headers['x-device-id'];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if session exists in database
    const { data: session, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('admin_id', decoded.id)
      .eq('device_id', deviceId)
      .eq('token', token)
      .single();
    
    if (error || !session) {
      return res.status(403).json({ message: 'Invalid session' });
    }

    // Check if session is expired
    if (new Date(session.expires_at) < new Date()) {
      // Delete expired session
      await supabase
        .from('sessions')
        .delete()
        .eq('id', session.id);
      
      return res.status(403).json({ message: 'Session expired' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Check if user is super admin
const isSuperAdmin = async (req, res, next) => {
  try {
    const { data, error } = await supabase
      .from('admins')
      .select('is_super')
      .eq('id', req.user.id)
      .single();

    if (error) {
      return res.status(500).json({ message: 'Database error', error });
    }

    if (!data || !data.is_super) {
      return res.status(403).json({ message: 'Requires super admin privileges' });
    }

    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// API Routes

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const deviceId = req.headers['x-device-id'];

    // Input validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    if (!deviceId) {
      return res.status(400).json({ message: 'Device ID is required' });
    }

    // Get admin from database
    const { data, error } = await supabase
      .from('admins')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !data) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, data.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check for existing sessions for this user
    const { data: existingSessions } = await supabase
      .from('sessions')
      .select('*')
      .eq('admin_id', data.id);

    // If there's a session with a different device ID, invalidate it
    if (existingSessions && existingSessions.length > 0) {
      const hasOtherDevice = existingSessions.some(session => session.device_id !== deviceId);
      
      if (hasOtherDevice) {
        // Delete all other sessions for this user
        await supabase
          .from('sessions')
          .delete()
          .eq('admin_id', data.id)
          .neq('device_id', deviceId);
      }
    }

    // Generate JWT token
    const tokenExpiry = '24h';
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours from now
    
    const token = jwt.sign(
      { id: data.id, username: data.username, is_super: data.is_super },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    // Store session in database
    await supabase
      .from('sessions')
      .upsert([{
        admin_id: data.id,
        device_id: deviceId,
        token: token,
        expires_at: expiresAt.toISOString()
      }], {
        onConflict: 'admin_id, device_id' // Update if this device already has a session
      });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: data.id,
        username: data.username,
        is_super: data.is_super
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});


// Logout route (client-side implementation)
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const deviceId = req.headers['x-device-id'];
    const token = req.headers['authorization'].split(' ')[1];
    
    // Remove session from database
    await supabase
      .from('sessions')
      .delete()
      .eq('admin_id', userId)
      .eq('device_id', deviceId)
      .eq('token', token);
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Check session endpoint
app.get('/api/check-session', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: {
      id: req.user.id,
      username: req.user.username,
      is_super: req.user.is_super
    }
  });
});

// Add admin route (super admin only)
app.post('/api/admins', authenticateToken, isSuperAdmin, async (req, res) => {
  try {
    const { username, password, is_super = false } = req.body;

    // Input validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Check if username already exists
    const { data: existingAdmin } = await supabase
      .from('admins')
      .select('id')
      .eq('username', username)
      .single();

    if (existingAdmin) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new admin
    const { data, error } = await supabase
      .from('admins')
      .insert([
        { username, password: hashedPassword, is_super }
      ])
      .select();

    if (error) {
      return res.status(500).json({ message: 'Failed to create admin', error });
    }

    // Remove password from response
    const newAdmin = data[0];
    delete newAdmin.password;

    res.status(201).json({
      message: 'Admin created successfully',
      admin: newAdmin
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all admins (super admin only)
app.get('/api/admins', authenticateToken, isSuperAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('admins')
      .select('id, username, created_at, is_super')
      .order('created_at');

    if (error) {
      return res.status(500).json({ message: 'Database error', error });
    }

    res.json({ admins: data });
  } catch (error) {
    console.error('Get admins error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete admin (super admin only)
app.delete('/api/admins/:id', authenticateToken, isSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if trying to delete self
    if (id === req.user.id) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    const { error } = await supabase
      .from('admins')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: 'Failed to delete admin', error });
    }

    res.json({ message: 'Admin deleted successfully' });
  } catch (error) {
    console.error('Delete admin error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Change password route
app.put('/api/admins/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Input validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new passwords are required' });
    }

    // Get admin from database
    const { data, error } = await supabase
      .from('admins')
      .select('password')
      .eq('id', userId)
      .single();

    if (error || !data) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, data.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    const { error: updateError } = await supabase
      .from('admins')
      .update({ password: hashedPassword })
      .eq('id', userId);

    if (updateError) {
      return res.status(500).json({ message: 'Failed to update password', error: updateError });
    }

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
