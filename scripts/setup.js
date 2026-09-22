/**
 * npm run setup → create .venv and pip install -r requirements.txt
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const isWin = process.platform === "win32";
const venvDir = path.join(root, ".venv");
const venvPython = isWin
  ? path.join(venvDir, "Scripts", "python.exe")
  : path.join(venvDir, "bin", "python");

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit", shell: isWin });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (!fs.existsSync(venvPython)) {
  console.log("Creating virtual environment (.venv)...");
  run(isWin ? "python" : "python3", ["-m", "venv", ".venv"]);
}

console.log("Installing Python packages...");
run(venvPython, ["-m", "pip", "install", "--upgrade", "pip"]);
run(venvPython, ["-m", "pip", "install", "-r", "requirements.txt"]);

console.log("\nDone. Start the site with:\n  npm run dev\n");
