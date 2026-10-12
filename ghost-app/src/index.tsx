import { render } from "solid-js/web";
import App from "./App";
import "./app.css";

// Disable Tauri's default browser context menu globally
document.addEventListener("contextmenu", (e) => e.preventDefault());

const root = document.getElementById("root");
render(() => <App />, root!);

// Devtools builds measure this window for the profiler; other builds drop this.
if (__GHOST_DEVTOOLS__) {
  import("./lib/devtools/frontend").then(({ startFrontendReports }) => startFrontendReports());
}
