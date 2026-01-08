import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";

export default function ActivitiesList() {

  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get("http://localhost:3000/api/activities")
      .then(res => {
        setActivities(res.data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  if (loading) return <h2>Ładowanie...</h2>;

  return (
    <>
      <h2>Lista aktywności</h2>

      <table border="1" cellPadding="8">
        <thead>
          <tr>
            <th>Nazwa</th>
            <th>Typ</th>
            <th>Dystans</th>
            <th>Szczegóły</th>
          </tr>
        </thead>

        <tbody>
          {activities.map(act => (
            <tr key={act.id}>
              <td>{act.name}</td>
              <td>{act.type}</td>
              <td>{act.distance_km} km</td>
              <td>
                <Link to={`/activity/${act.id}`}>
                  Otwórz
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
