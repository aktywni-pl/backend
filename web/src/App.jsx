import { Routes, Route, Link } from "react-router-dom";
import ActivitiesList from "./components/ActivitiesList.jsx";
import ActivityDetails from "./components/ActivityDetails.jsx";

export default function App() {
  return (
    <div style={{ padding: "20px" }}>
      <h1>Aktywni.pl — Web</h1>

      <nav style={{ marginBottom: "10px" }}>
        <Link to="/">Lista aktywności</Link>
      </nav>

      <Routes>
        <Route path="/" element={<ActivitiesList />} />
        <Route path="/activity/:id" element={<ActivityDetails />} />
      </Routes>
    </div>
  );
}
