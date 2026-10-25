/*
 * MAKKADi desktop shell.
 * Starts the bundled backend (PyInstaller) on 127.0.0.1 with a free port and a
 * per-user data directory, waits for /api/v1/health, then opens the UI in a
 * locked-down BrowserWindow. The backend is stopped when the app quits.
 */
const { app, BrowserWindow, dialog, shell, Menu } = require("electron");
const { spawn } = require("node:child_process");
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");
const http = require("node:http");

let backend = null;
let mainWindow = null;
let baseUrl = null;
const logLines = [];

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function backendCommand(port, dataDir) {
  const args = ["--host", "127.0.0.1", "--port", String(port), "--data-dir", dataDir];
  if (app.isPackaged) {
    const exe = process.platform === "win32" ? "makkadi-backend.exe" : "makkadi-backend";
    return { cmd: path.join(process.resourcesPath, "backend", exe), args, cwd: path.join(process.resourcesPath, "backend") };
  }
  // Development: run the Python backend from the repository (venv expected in backend/.venv or PATH).
  const backendDir = path.resolve(__dirname, "..", "..", "backend");
  const venvPython = process.platform === "win32" ? path.join(backendDir, ".venv", "Scripts", "python.exe") : path.join(backendDir, ".venv", "bin", "python");
  const python = fs.existsSync(venvPython) ? venvPython : (process.platform === "win32" ? "python" : "python3");
  return { cmd: python, args: ["-m", "app.run", ...args, "--static-dir", path.resolve(backendDir, "..", "frontend", "dist")], cwd: backendDir };
}

function waitForHealth(url, timeoutMs = 60000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      http.get(url + "api/v1/health", (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry();
      }).on("error", retry);
    };
    const retry = () => (Date.now() - started > timeoutMs ? reject(new Error("Le serveur MAKKADi n'a pas démarré")) : setTimeout(tick, 400));
    tick();
  });
}

async function startBackend() {
  const port = await freePort();
  const dataDir = path.join(app.getPath("userData"), "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const { cmd, args, cwd } = backendCommand(port, dataDir);
  backend = spawn(cmd, args, {
    cwd,
    windowsHide: true,
    env: { ...process.env, MAKKADI_HOST: "127.0.0.1", MAKKADI_ALLOW_REMOTE_BIND: "false" },
  });
  const keep = (chunk) => { logLines.push(...String(chunk).split("\n")); while (logLines.length > 400) logLines.shift(); };
  backend.stdout.on("data", keep);
  backend.stderr.on("data", keep);
  backend.on("exit", (code) => {
    if (!app.isQuitting) {
      dialog.showErrorBox("MAKKADi", `Le serveur local s'est arrêté (code ${code}).\n\n${logLines.slice(-15).join("\n")}`);
      app.quit();
    }
  });
  baseUrl = `http://127.0.0.1:${port}/`;
  await waitForHealth(baseUrl);
  return { baseUrl, dataDir };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: "#05070b",
    title: "MAKKADi",
    icon: path.join(__dirname, "..", "build", "icon.png"),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
      preload: path.join(__dirname, "preload.js"),
    },
  });
  // Only the local backend origin may be displayed; everything else opens in the system browser (https only).
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith(baseUrl)) {
      event.preventDefault();
      if (url.startsWith("https://")) shell.openExternal(url);
    }
  });
  mainWindow.webContents.session.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  mainWindow.loadURL(baseUrl);
}

function stopBackend() {
  if (backend && !backend.killed) {
    if (process.platform === "win32") spawn("taskkill", ["/pid", String(backend.pid), "/t", "/f"], { windowsHide: true });
    else backend.kill("SIGTERM");
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => { if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.focus(); } });
  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null);
    try {
      await startBackend();
      createWindow();
    } catch (err) {
      dialog.showErrorBox("MAKKADi", `${err.message}\n\n${logLines.slice(-20).join("\n")}`);
      app.quit();
    }
  });
  app.on("before-quit", () => { app.isQuitting = true; stopBackend(); });
  app.on("window-all-closed", () => app.quit());
}
