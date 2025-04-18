// setup.js - Script to create the first super admin
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');
const readline = require('readline');

// Load environment variables
dotenv.config();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function createSuperAdmin() {
  console.log('===== Create First Super Admin =====');
  
  // Get admin details
  const username = await new Promise(resolve => {
    rl.question('Enter admin username: ', resolve);
  });
  
  const password = await new Promise(resolve => {
    rl.question('Enter admin password: ', resolve);
  });

  try {
    // Check if username already exists
    const { data: existingAdmin } = await supabase
      .from('admins')
      .select('id')
      .eq('username', username)
      .single();

    if (existingAdmin) {
      console.error('Error: Username already exists');
      rl.close();
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create super admin
    const { data, error } = await supabase
      .from('admins')
      .insert([
        { username, password: hashedPassword, is_super: true }
      ])
      .select();

    if (error) {
      console.error('Error creating super admin:', error);
      rl.close();
      return;
    }

    console.log('\nSuper admin created successfully:');
    console.log(`ID: ${data[0].id}`);
    console.log(`Username: ${data[0].username}`);
    console.log(`Created at: ${data[0].created_at}`);
    console.log('Super admin: true');
  } catch (error) {
    console.error('Server error:', error);
  } finally {
    rl.close();
  }
}

createSuperAdmin();