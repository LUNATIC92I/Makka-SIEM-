// No Node.js API is exposed to the web content (contextIsolation + sandbox).
const { contextBridge } = require("electron");
contextBridge.exposeInMainWorld("makkadiDesktop", { platform: process.platform, desktop: true });
