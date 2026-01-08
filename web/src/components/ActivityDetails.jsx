import { useParams } from "react-router-dom";
import { useEffect, useState, useRef } from "react";
import axios from "axios";
import L from "leaflet";

export default function ActivityDetails() {
  const { id } = useParams();
  const [activity, setActivity] = useState(null);
  const mapRef = useRef(null); // przechowujemy instancję mapy

  // 1. Pobieramy aktywność (bez mapy)
  useEffect(() => {
    axios
      .get("http://localhost:3000/api/activities")
      .then((res) => {
        const found = res.data.find((a) => String(a.id) === String(id));
        setActivity(found || null);
      })
      .catch((err) => {
        console.error("Błąd przy pobieraniu aktywności:", err);
      });
  }, [id]);

  // 2. Gdy aktywność jest już znana i div#map jest w DOM – inicjalizujemy mapę + track
  useEffect(() => {
    // dopóki nie mamy aktywności, nie ruszamy mapy
    if (!activity) return;

    // zabezpieczenie: jak mapa już była, usuwamy starą
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }

    // inicjalizacja mapy
    const map = L.map("map").setView([51.111, 17.02], 14);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
    }).addTo(map);

    mapRef.current = map;

    // pobranie śladu GPS i dorysowanie polyline
    axios
      .get(`http://localhost:3000/api/activities/${id}/track`)
      .then((trackRes) => {
        if (!trackRes.data || !trackRes.data.points) return;

        const latlngs = trackRes.data.points.map((p) => [p.lat, p.lon]);

        if (!latlngs.length) return;

        const polyline = L.polyline(latlngs).addTo(map);
        map.fitBounds(polyline.getBounds());
      })
      .catch((err) => {
        console.error("Błąd przy pobieraniu śladu GPS:", err);
      });

    // sprzątanie po odmontowaniu
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [activity, id]);

  if (!activity) return <h2>Ładowanie...</h2>;

  return (
    <>
      <h2>Szczegóły aktywności</h2>

      <p>
        <b>Nazwa:</b> {activity.name}
      </p>
      <p>
        <b>Typ:</b> {activity.type}
      </p>
      <p>
        <b>Dystans:</b> {activity.distance_km} km
      </p>

      <div
        id="map"
        style={{
          height: "400px",
          marginTop: "15px",
          border: "1px solid #333",
        }}
      />
    </>
  );
}
