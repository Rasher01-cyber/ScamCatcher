/**
 * npm run dev → starts Flask (same idea as a Vite/React dev server).
 */
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const isWin = process.platform === "win32";
const venvPython = isWin
  ? path.join(root, ".venv", "Scripts", "python.exe")
  : path.join(root, ".venv", "bin", "python");

function pickPython() {
  if (fs.existsSync(venvPython)) return venvPython;
  return isWin ? "python" : "python3";
}

const python = pickPython();
if (!fs.existsSync(venvPython)) {
  console.log("No .venv found. Creating it and installing packages...");
  console.log("Or run: npm run setup\n");
}

console.log("Starting ScamCatcherrr → http://127.0.0.1:5000/\n");
console.log(`Using: ${python}\n`);

const child = spawn(python, ["app.py"], {
  cwd: root,
  stdio: "inherit",
  shell: isWin,
});

child.on("error", (err) => {
  console.error("Failed to start:", err.message);
  console.error("\nTry:\n  npm run setup\n  npm run dev\n");
  process.exit(1);
});

child.on("exit", (code) => process.exit(code ?? 0));
