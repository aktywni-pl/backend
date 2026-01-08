const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Prosty endpoint testowy
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'API działa' });
});

// Przykładowe aktywności (na razie na sztywno)
const activities = [
  {
    id: 1,
    name: 'Wieczorny bieg',
    type: 'run',
    distance_km: 5.2,
    duration_min: 30,
    started_at: '2025-03-01T17:03:00Z'
  },
  {
    id: 2,
    name: 'Spacer z psem',
    type: 'walk',
    distance_km: 2.1,
    duration_min: 25,
    started_at: '2025-03-02T18:10:00Z'
  }
];

const tracks = {
  1: {
    activity_id: 1,
    points: [
      { lat: 51.1110, lon: 17.0200, timestamp: '2025-03-01T17:03:00Z' },
      { lat: 51.1120, lon: 17.0210, timestamp: '2025-03-01T17:03:10Z' },
      { lat: 51.1130, lon: 17.0220, timestamp: '2025-03-01T17:03:20Z' },
      { lat: 51.1140, lon: 17.0230, timestamp: '2025-03-01T17:03:30Z' }
    ]
  },
  2: {
    activity_id: 2,
    points: [
      { lat: 51.1200, lon: 17.0300, timestamp: '2025-03-02T18:10:00Z' },
      { lat: 51.1205, lon: 17.0305, timestamp: '2025-03-02T18:10:15Z' },
      { lat: 51.1210, lon: 17.0310, timestamp: '2025-03-02T18:10:30Z' }
    ]
  }
};

// Lista aktywności
app.get('/api/activities', (req, res) => {
  console.log('GET /api/activities');
  res.json(activities);
});

// Ślad GPS dla konkretnej aktywności
app.get('/api/activities/:id/track', (req, res) => {
  const id = Number(req.params.id);
  console.log('GET /api/activities/' + id + '/track'); // <--- LOG

  const track = tracks[id];

  if (!track) {
    return res.status(404).json({ error: 'Track not found for activity ' + id });
  }

  res.json(track);
});

app.listen(PORT, () => {
  console.log('API działa na porcie ' + PORT);
});
