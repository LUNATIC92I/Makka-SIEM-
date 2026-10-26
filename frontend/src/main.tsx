import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./hooks/useAuth";
import { FxProvider } from "./fx/useFx";
import "./index.css";
import "leaflet/dist/leaflet.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <FxProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </FxProvider>
    </HashRouter>
  </React.StrictMode>,
);
