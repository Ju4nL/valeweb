// valeweb-backend/index.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const pg = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(bodyParser.json());

const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Middleware para verificar token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Crear usuario
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await pool.query(
    'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
    [name, email, hashedPassword, role || 'user']
  );
  res.sendStatus(201);
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0) return res.sendStatus(401);

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.sendStatus(403);

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
  res.json({ token });
});

// Obtener todos los usuarios
app.get('/users', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT id, name, email, role FROM users');
  res.json(result.rows);
});

// Eliminar usuario (solo scrum)
app.delete('/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'scrum') return res.sendStatus(403);
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.sendStatus(200);
});

// Cambiar Scrum Master
app.put('/users/:id/make-scrum', authenticateToken, async (req, res) => {
  if (req.user.role !== 'scrum') return res.sendStatus(403);
  await pool.query("UPDATE users SET role = 'user' WHERE role = 'scrum'");
  await pool.query("UPDATE users SET role = 'scrum' WHERE id = $1", [req.params.id]);
  res.sendStatus(200);
});

// Crear vales (scrum asigna)
app.post('/vales', authenticateToken, async (req, res) => {
  if (req.user.role !== 'scrum') return res.sendStatus(403);
  const { description, assigned_to, expires_at } = req.body;
  await pool.query(
    'INSERT INTO vales (description, assigned_to, assigned_by, expires_at) VALUES ($1, $2, $3, $4)',
    [description, assigned_to, req.user.id, expires_at]
  );
  res.sendStatus(201);
});

// Ver vales asignados a mí
app.get('/vales', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM vales WHERE assigned_to = $1 AND expires_at > NOW()',
    [req.user.id]
  );
  res.json(result.rows);
});

// Canjear vale
app.post('/vales/:id/canjear', authenticateToken, async (req, res) => {
  const { to_user } = req.body;
  const vale_id = req.params.id;
  await pool.query(
    'INSERT INTO vale_canjeo (vale_id, from_user, to_user) VALUES ($1, $2, $3)',
    [vale_id, req.user.id, to_user]
  );
  res.sendStatus(201);
});

// Aceptar vale
app.put('/vale_canjeo/:id/aceptar', authenticateToken, async (req, res) => {
  const id = req.params.id;
  await pool.query(
    'UPDATE vale_canjeo SET accepted = TRUE, accepted_at = NOW() WHERE id = $1 AND to_user = $2',
    [id, req.user.id]
  );
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`ValeWeb API corriendo en http://localhost:${PORT}`);
});
