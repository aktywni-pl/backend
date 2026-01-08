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

// Przykładowy endpoint z listą aktywności (na razie na sztywno)
app.get('/api/activities', (req, res) => {
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

  res.json(activities);
});

app.listen(PORT, () => {
  console.log('API działa na porcie ' + PORT);
});
