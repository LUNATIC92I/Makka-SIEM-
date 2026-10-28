// No Node.js API is exposed to the web content (contextIsolation + sandbox).
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("makkadiDesktop", {
  platform: process.platform,
  desktop: true,
  // Opens the local password reset tool (console window); takes no argument from the page.
  openPasswordReset: () => ipcRenderer.invoke("makkadi:open-password-reset"),
});
