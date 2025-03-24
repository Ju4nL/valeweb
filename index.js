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



const allowedOrigins = process.env.FRONTEND_URLS?.split(',') || [];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("No permitido por CORS"));
    }
  },
  credentials: true,
}));

app.options('*', cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("No permitido por CORS"));
    }
  },
  credentials: true,
}));




app.use(bodyParser.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
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
  const { description, assigned_to, expires_at, canjeadores } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO vales (description, assigned_to, assigned_by, expires_at) VALUES ($1, $2, $3, $4) RETURNING id',
      [description, assigned_to, req.user.id, expires_at]
    );

    const valeId = result.rows[0].id;

    for (const to_user of canjeadores) {
      await pool.query(
        'INSERT INTO vale_canjeo (vale_id, from_user, to_user, accepted) VALUES ($1, $2, $3, $4)',
        [valeId, assigned_to, to_user, null] // null = aún no se ha enviado
      );
    }

    res.sendStatus(201);
  } catch (err) {
    console.error("Error creando vale:", err.message);
    res.sendStatus(500);
  }
});

// Mostrar vales asignados a mí que aún no han sido enviados
app.get('/vales', authenticateToken, async (req, res) => {
  const result = await pool.query(
    `SELECT vc.id AS canjeo_id, v.id AS vale_id, v.description, v.expires_at,
            u.name AS to_user_name, vc.accepted
     FROM vales v
     JOIN vale_canjeo vc ON vc.vale_id = v.id
     JOIN users u ON vc.to_user = u.id
     WHERE v.assigned_to = $1
       AND v.expires_at > NOW()
       AND (vc.accepted IS NULL OR vc.accepted = FALSE)`,
    [req.user.id]
  );
  res.json(result.rows);
});


// Enviar vale para que el receptor pueda aceptarlo (cambia null -> FALSE)
app.put('/vale_canjeo/:id/enviar', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'UPDATE vale_canjeo SET accepted = FALSE WHERE id = $1 AND from_user = $2 AND accepted IS NULL',
      [id, req.user.id]
    );
    res.sendStatus(200);
  } catch (err) {
    console.error("Error enviando vale:", err.message);
    res.sendStatus(500);
  }
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

// Ver vales que me canjearon y aún no he aceptado (solo los enviados)
app.get('/vale_canjeo/pendientes', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT vc.id, v.description, u.name AS from_user, vc.accepted FROM vale_canjeo vc ' +
    'JOIN vales v ON vc.vale_id = v.id ' +
    'JOIN users u ON vc.from_user = u.id ' +
    'WHERE vc.to_user = $1 AND vc.accepted = FALSE',
    [req.user.id]
  );
  res.json(result.rows);
});

app.listen(PORT, () => {
  console.log(`ValeWeb API corriendo en http://localhost:${PORT}`);
});
