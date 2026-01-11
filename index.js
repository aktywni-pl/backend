const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");

const openapiDocument = YAML.load("./openapi.yaml");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token';

const dbConfig = {
  host: process.env.DB_HOST || 'mariadb',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'aktywni',
  password: process.env.DB_PASSWORD || 'aktywni123',
  database: process.env.DB_NAME || 'aktywni',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: 'Z'
};

let pool;

async function initDbWithRetry() {
  const maxRetries = 30;
  for (let i = 1; i <= maxRetries; i++) {
    try {
      pool = mysql.createPool(dbConfig);
      await pool.query('SELECT 1');
      console.log('DB connected');
      return;
    } catch (err) {
      console.log(`DB not ready (${i}/${maxRetries})...`);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw new Error('DB connection failed after retries');
}

// ===== SWAGGER =====
app.use("/api/documentation", swaggerUi.serve, swaggerUi.setup(openapiDocument));

// ===== ADMIN AUTH =====
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Forbidden. Admin token required.' });
  }
  next();
}

// ===== HEALTH =====
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ status: 'error', message: 'DB not ready' });
  }
});

// ===== REGISTER =====
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    // sprawdzenie czy email zajęty
    const [exists] = await pool.query(
      'SELECT id FROM users WHERE email=? LIMIT 1',
      [email]
    );

    if (exists.length) {
      return res.status(409).json({ error: 'email already exists' });
    }

    // zapis usera (PLAINTEXT – zgodnie z loginem)
    const [result] = await pool.query(
      'INSERT INTO users (email, password, role) VALUES (?,?,?)',
      [email, password, 'user']
    );

    res.status(201).json({
      id: result.insertId,
      email,
      role: 'user',
      token: 'user-token'
    });

  } catch (err) {
    console.error('REGISTER error:', err);
    res.status(500).json({ error: 'internal error' });
  }
});


// ===== LOGIN =====
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const [rows] = await pool.query(
    'SELECT id, email, role FROM users WHERE email=? AND password=? LIMIT 1',
    [email, password]
  );

  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

  const user = rows[0];
  const token = user.role === 'admin' ? ADMIN_TOKEN : 'user-token';

  res.json({ id: user.id, email: user.email, role: user.role, token });
});

// ===== USER: LIST ACTIVITIES =====
app.get('/api/activities', async (req, res) => {
  // opcjonalnie: ?userId=2
  const { userId } = req.query;

  let sql = 'SELECT id, user_id, name, type, distance_km, duration_min, started_at, start_place, end_place FROM activities';
  const params = [];

  if (userId) {
    sql += ' WHERE user_id=?';
    params.push(Number(userId));
  }

  sql += ' ORDER BY started_at DESC';

  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

// ===== USER: DETAILS =====
app.get('/api/activities/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.query(
    'SELECT id, user_id, name, type, distance_km, duration_min, started_at, start_place, end_place FROM activities WHERE id=? LIMIT 1',
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Activity not found' });
  res.json(rows[0]);
});

// ===== MOBILE: CREATE ACTIVITY (TRWAŁE) =====
app.post('/api/activities', async (req, res) => {
  const { user_id, name, type, distance_km, duration_min, started_at } = req.body || {};

  if (!user_id || !name || !type || started_at === undefined) {
    return res.status(400).json({ error: 'user_id, name, type, started_at required' });
  }

  const startedAt = new Date(started_at);
  if (Number.isNaN(startedAt.getTime())) {
    return res.status(400).json({ error: 'started_at invalid date' });
  }

  const [result] = await pool.query(
    'INSERT INTO activities (user_id, name, type, distance_km, duration_min, started_at) VALUES (?,?,?,?,?,?)',
    [
      Number(user_id),
      String(name),
      String(type),
      Number(distance_km || 0),
      Number(duration_min || 0),
      startedAt.toISOString().slice(0, 19).replace('T', ' ')
    ]
  );

  res.status(201).json({ id: result.insertId });
});

// ===== USER: GET TRACK =====
app.get('/api/activities/:id/track', async (req, res) => {
  const id = Number(req.params.id);

  const [act] = await pool.query('SELECT id FROM activities WHERE id=? LIMIT 1', [id]);
  if (!act.length) return res.status(404).json({ error: 'Activity not found' });

  const [rows] = await pool.query(
    'SELECT lat, lon, timestamp FROM activity_points WHERE activity_id=? ORDER BY timestamp ASC',
    [id]
  );

  res.json({
    activity_id: id,
    points: rows.map(r => ({
      lat: Number(r.lat),
      lon: Number(r.lon),
      timestamp: new Date(r.timestamp).toISOString()
    }))
  });
});

// ===== MOBILE: PUT TRACK (replace) =====
app.put('/api/activities/:id/track', async (req, res) => {
  const id = Number(req.params.id);
  const { points } = req.body || {};
  if (!Array.isArray(points) || points.length === 0) {
    return res.status(400).json({ error: 'points array required' });
  }

  const [act] = await pool.query('SELECT id FROM activities WHERE id=? LIMIT 1', [id]);
  if (!act.length) return res.status(404).json({ error: 'Activity not found' });

  // replace track: delete old, insert new
  await pool.query('DELETE FROM activity_points WHERE activity_id=?', [id]);

  const values = points.map(p => {
    const ts = new Date(p.timestamp);
    if (Number.isNaN(ts.getTime())) throw new Error('Invalid timestamp in points');
    return [
      id,
      Number(p.lat),
      Number(p.lon),
      ts.toISOString().slice(0, 19).replace('T', ' ')
    ];
  });

  await pool.query(
    'INSERT INTO activity_points (activity_id, lat, lon, timestamp) VALUES ?',
    [values]
  );

  res.status(204).end();
});

// ===== ADMIN: USERS =====
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT id, email, role, created_at FROM users ORDER BY id ASC');
  res.json(rows);
});

// ===== ADMIN: ACTIVITIES + FILTERS =====
app.get('/api/admin/activities', requireAdmin, async (req, res) => {
  const { userId, type, minDistance, maxDistance, dateFrom, dateTo, q } = req.query;

  let sql = 'SELECT id, user_id, name, type, distance_km, duration_min, started_at, start_place, end_place FROM activities WHERE 1=1';
  const params = [];

  if (userId) { sql += ' AND user_id=?'; params.push(Number(userId)); }
  if (type) { sql += ' AND type=?'; params.push(String(type)); }
    if (q) { sql += " AND name LIKE ?"; params.push("%" + String(q) + "%"); }
if (minDistance) { sql += ' AND distance_km>=?'; params.push(Number(minDistance)); }
  if (maxDistance) { sql += ' AND distance_km<=?'; params.push(Number(maxDistance)); }

  if (dateFrom) {
    const d = new Date(dateFrom);
    if (!Number.isNaN(d.getTime())) {
      sql += ' AND started_at>=?';
      params.push(d.toISOString().slice(0, 19).replace('T', ' '));
    }
  }
  if (dateTo) {
    const d = new Date(dateTo);
    if (!Number.isNaN(d.getTime())) {
      sql += ' AND started_at<=?';
      params.push(d.toISOString().slice(0, 19).replace('T', ' '));
    }
  }

  sql += ' ORDER BY started_at DESC';

  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

// ===== ADMIN: DELETE ACTIVITY =====
app.delete('/api/admin/activities/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const [result] = await pool.query('DELETE FROM activities WHERE id=?', [id]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'Activity not found' });
  res.status(204).end();
});

// ===== ADMIN: STATS =====
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [[u]] = await pool.query('SELECT COUNT(*) AS totalUsers FROM users');
  const [[a]] = await pool.query('SELECT COUNT(*) AS totalActivities, COALESCE(SUM(distance_km),0) AS totalDistance FROM activities');

  res.json({
    totalUsers: Number(u.totalUsers),
    totalActivities: Number(a.totalActivities),
    totalDistance: Number(a.totalDistance)
  });
});

// ===== GPX EXPORT =====
app.get('/api/activities/:id/export.gpx', async (req, res) => {
  const id = Number(req.params.id);

  const [actRows] = await pool.query(
    'SELECT id, name, type FROM activities WHERE id=? LIMIT 1',
    [id]
  );
  if (!actRows.length) return res.status(404).send('Activity not found');

  const activity = actRows[0];

  const [pts] = await pool.query(
    'SELECT lat, lon, timestamp FROM activity_points WHERE activity_id=? ORDER BY timestamp ASC',
    [id]
  );
  if (!pts.length) return res.status(404).send('Track not found');

  const gpxPoints = pts.map(p => {
    const iso = new Date(p.timestamp).toISOString();
    return `<trkpt lat="${Number(p.lat)}" lon="${Number(p.lon)}"><time>${iso}</time></trkpt>`;
  }).join("\n");

  const gpx = `<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="Aktywni.pl">
  <trk>
    <name>${activity.name}</name>
    <type>${activity.type}</type>
    <trkseg>
${gpxPoints}
    </trkseg>
  </trk>
</gpx>`;

  res.setHeader('Content-Type', 'application/gpx+xml');
  res.setHeader('Content-Disposition', 'attachment; filename="activity-' + id + '.gpx"');
  res.send(gpx);
});

// ===== START =====
initDbWithRetry()
  .then(() => {
    app.listen(PORT, () => console.log('API działa na porcie ' + PORT));
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
