require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false
  }  
});

async function crearUsuarioJuan() {
  const name = 'Juan';
  const email = 'juanlozadacochaches@gmail.com';
  const password = '12345';
  const role = 'scrum';

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
      [name, email, hashedPassword, role]
    );

    console.log('✅ Usuario Juan creado como SCRUM');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error al crear a Juan:', err.message);
    process.exit(1);
  }
}

crearUsuarioJuan();
