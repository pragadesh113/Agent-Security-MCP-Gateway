import { execFileSync } from "node:child_process";

const command = process.platform === "win32" ? process.env.ComSpec : "npm";
const commandArguments = process.platform === "win32"
  ? ["/d", "/s", "/c", "npm pack --dry-run --json"]
  : ["pack", "--dry-run", "--json"];
const output = execFileSync(command, commandArguments, {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"]
});

const reports = JSON.parse(output);
const files = reports.flatMap((report) => report.files ?? []).map((file) => file.path);
const forbiddenPrefixes = ["phase-1/", "test/", "dist/", "paper/", "tmp/"];
const forbidden = files.filter((file) => forbiddenPrefixes.some((prefix) => file.startsWith(prefix)));

if (forbidden.length > 0) {
  console.error(`Package boundary violation: ${forbidden.join(", ")}`);
  process.exit(1);
}

console.log(`Package boundary verified: ${files.length} files; archived Phase 1, tests, dist, paper artifacts, and scratch output excluded.`);
