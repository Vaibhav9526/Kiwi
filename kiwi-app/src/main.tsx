import React from "react";
import ReactDOM from "react-dom/client";
import "./theme.css";
import "./mailspring-tokens.css";
import "./shell.css";
import "./motion.css";
import "./themes"; // T-268: stock theme packages + sideloaded-theme restore
import App from "./App";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
