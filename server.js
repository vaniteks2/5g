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

// Telegram group management endpoints
const { Telegraf } = require('telegraf');

// Get all telegram groups
app.get('/api/telegram-groups', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('telegram_groups')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ message: 'Database error', error });
    }

    res.json({ groups: data });
  } catch (error) {
    console.error('Get telegram groups error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Add new telegram group
app.post('/api/telegram-groups', authenticateToken, async (req, res) => {
  try {
    const { group_name, group_id, username, bot_token } = req.body;

    // Input validation
    if (!group_name || !group_id || !bot_token) {
      return res.status(400).json({ message: 'Group name, ID and bot token are required' });
    }

    // Test the bot token by getting chat info
    try {
      const bot = new Telegraf(bot_token);
      const chat = await bot.telegram.getChat(group_id);
      
      if (!chat) {
        return res.status(400).json({ message: 'Invalid group ID or bot token' });
      }
      
      // Get member count
      let memberCount = 0;
      if (chat.type === 'channel') {
        // For channels, we can't get exact member count through API
        memberCount = -1; // Use -1 to indicate we need to check via botfather
      } else {
        // For groups, we can get member count
        const chatMembers = await bot.telegram.getChatMembersCount(group_id);
        memberCount = chatMembers;
      }

      // Add group to database
      const { data, error } = await supabase
        .from('telegram_groups')
        .insert([{
          group_name,
          group_id,
          username: username || null,
          bot_token,
          member_count: memberCount,
          last_updated: new Date().toISOString(),
          created_by: req.user.id
        }])
        .select();

      if (error) {
        return res.status(500).json({ message: 'Failed to add telegram group', error });
      }

      res.status(201).json({
        message: 'Telegram group added successfully',
        group: data[0]
      });
    } catch (botError) {
      return res.status(400).json({ 
        message: 'Failed to connect to Telegram. Please check your bot token and group ID.',
        error: botError.message
      });
    }
  } catch (error) {
    console.error('Add telegram group error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update telegram group
app.put('/api/telegram-groups/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { group_name, group_id, username, bot_token } = req.body;

    // Input validation
    if (!group_name || !group_id || !bot_token) {
      return res.status(400).json({ message: 'Group name, ID and bot token are required' });
    }

    // Test the bot token by getting chat info
    try {
      const bot = new Telegraf(bot_token);
      const chat = await bot.telegram.getChat(group_id);
      
      if (!chat) {
        return res.status(400).json({ message: 'Invalid group ID or bot token' });
      }
      
      // Get member count
      let memberCount = 0;
      if (chat.type === 'channel') {
        // For channels, we'll need to use different approach
        memberCount = -1;
      } else {
        // For groups, we can get member count
        const chatMembers = await bot.telegram.getChatMembersCount(group_id);
        memberCount = chatMembers;
      }

      // Update group in database
      const { data, error } = await supabase
        .from('telegram_groups')
        .update({
          group_name,
          group_id,
          username: username || null,
          bot_token,
          member_count: memberCount,
          last_updated: new Date().toISOString()
        })
        .eq('id', id)
        .select();

      if (error) {
        return res.status(500).json({ message: 'Failed to update telegram group', error });
      }

      if (!data || data.length === 0) {
        return res.status(404).json({ message: 'Group not found' });
      }

      res.json({
        message: 'Telegram group updated successfully',
        group: data[0]
      });
    } catch (botError) {
      return res.status(400).json({ 
        message: 'Failed to connect to Telegram. Please check your bot token and group ID.',
        error: botError.message
      });
    }
  } catch (error) {
    console.error('Update telegram group error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete telegram group
app.delete('/api/telegram-groups/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from('telegram_groups')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: 'Failed to delete telegram group', error });
    }

    res.json({ message: 'Telegram group deleted successfully' });
  } catch (error) {
    console.error('Delete telegram group error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Refresh member count for a telegram group
app.post('/api/telegram-groups/:id/refresh', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get group from database
    const { data: group, error: groupError } = await supabase
      .from('telegram_groups')
      .select('*')
      .eq('id', id)
      .single();

    if (groupError || !group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Connect to Telegram API
    try {
      const bot = new Telegraf(group.bot_token);
      
      // Get chat info to verify bot access
      const chat = await bot.telegram.getChat(group.group_id);
      
      if (!chat) {
        return res.status(400).json({ message: 'Bot could not access group' });
      }
      
      // Get member count
      let memberCount = 0;
      if (chat.type === 'channel') {
        // For channels, we cannot get exact member count
        memberCount = -1; // Use -1 to indicate we need to check via botfather
      } else {
        // For groups, we can get member count
        const chatMembers = await bot.telegram.getChatMembersCount(group.group_id);
        memberCount = chatMembers;
      }

      // Update group in database
      const { data, error } = await supabase
        .from('telegram_groups')
        .update({
          member_count: memberCount,
          last_updated: new Date().toISOString()
        })
        .eq('id', id)
        .select();

      if (error) {
        return res.status(500).json({ message: 'Failed to update member count', error });
      }

      res.json({
        message: 'Member count refreshed successfully',
        group: data[0]
      });
    } catch (botError) {
      return res.status(400).json({ 
        message: 'Failed to connect to Telegram. Please check your bot token and group ID.',
        error: botError.message
      });
    }
  } catch (error) {
    console.error('Refresh member count error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Refresh all groups member count
app.post('/api/telegram-groups/refresh-all', authenticateToken, async (req, res) => {
  try {
    // Get all groups from database
    const { data: groups, error: groupsError } = await supabase
      .from('telegram_groups')
      .select('*');

    if (groupsError) {
      return res.status(500).json({ message: 'Failed to fetch groups', error: groupsError });
    }

    const results = [];
    // Process each group
    for (const group of groups) {
      try {
        const bot = new Telegraf(group.bot_token);
        
        // Get chat info
        const chat = await bot.telegram.getChat(group.group_id);
        
        // Get member count
        let memberCount = 0;
        if (chat.type === 'channel') {
          memberCount = -1; // Use -1 to indicate we need to check via botfather
        } else {
          const chatMembers = await bot.telegram.getChatMembersCount(group.group_id);
          memberCount = chatMembers;
        }

        // Update group in database
        const { data, error } = await supabase
          .from('telegram_groups')
          .update({
            member_count: memberCount,
            last_updated: new Date().toISOString()
          })
          .eq('id', group.id)
          .select();

        if (error) {
          results.push({
            id: group.id,
            success: false,
            message: 'Database update failed',
            error
          });
        } else {
          results.push({
            id: group.id,
            success: true,
            group: data[0]
          });
        }
      } catch (botError) {
        results.push({
          id: group.id,
          success: false,
          message: 'Telegram API error',
          error: botError.message
        });
      }
    }

    res.json({
      message: 'Bulk refresh completed',
      results
    });
  } catch (error) {
    console.error('Refresh all groups error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
