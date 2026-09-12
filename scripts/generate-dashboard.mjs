import { writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { buildDashboardStatus } from "./dashboard-status.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = path.join(root, "dashboard");
const payload = await buildDashboardStatus(root);
await mkdir(outputDir, { recursive: true });
await writeFile(path.join(outputDir, "status.json"), `${JSON.stringify(payload, null, 2)}\n`, "utf8");
console.log(`Dashboard status generated at ${path.relative(root, path.join(outputDir, "status.json"))}`);
