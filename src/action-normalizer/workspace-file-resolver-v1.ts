import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import type { BigIntStats } from "node:fs";
import path from "node:path";
import { z } from "zod";

const MAX_BYTES = 1024 * 1024;
export const WorkspaceFileResolutionReasonV1Schema = z.enum([
  "INVALID_INPUT", "UNSUPPORTED_TOOL", "UNSUPPORTED_SYNTAX", "UNKNOWN_ALIAS",
  "UNSAFE_PATH", "ROOT_UNAVAILABLE", "FILESYSTEM_UNAVAILABLE", "LINK_UNSUPPORTED",
  "NOT_REGULAR_FILE", "IDENTITY_UNAVAILABLE", "FILE_TOO_LARGE", "STATE_CHANGED"
]);
type Reason = z.infer<typeof WorkspaceFileResolutionReasonV1Schema>;
export const WorkspaceFileRequestV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"), tool: z.string().min(1).max(128), arguments: z.unknown()
}).strict();
export const WorkspaceFileResolutionV1Schema = z.discriminatedUnion("status", [
  z.object({
    schemaVersion: z.literal("1.0.0"), status: z.literal("RESOLVED"),
    effect: z.enum(["READ", "WRITE", "DELETE"]),
    resource: z.object({ resourceId: z.string().regex(/^file:[a-f0-9]{64}$/),
      relativePath: z.string().min(1).max(1024), stateDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/) }).strict(),
    reason: z.null()
  }).strict(),
  z.object({ schemaVersion: z.literal("1.0.0"), status: z.literal("UNRESOLVED"),
    effect: z.literal("UNKNOWN"), resource: z.null(), reason: WorkspaceFileResolutionReasonV1Schema }).strict()
]);
export type WorkspaceFileResolutionV1 = z.infer<typeof WorkspaceFileResolutionV1Schema>;
export const workspaceFileResolutionV1Schema = WorkspaceFileResolutionV1Schema;
export interface WorkspaceFileResolverOptionsV1 {
  rootDirectory: string;
  workspaceId: string;
  aliases?: Readonly<Record<string, string>>;
}
const unresolved = (reason: Reason): WorkspaceFileResolutionV1 => ({
  schemaVersion: "1.0.0", status: "UNRESOLVED", effect: "UNKNOWN", resource: null, reason
});
const hash = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const identity = (s: BigIntStats): string => `${s.dev.toString()}:${s.ino.toString()}`;
const stamp = (s: BigIntStats): string => [identity(s), s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs, s.birthtimeNs].join(":");
const validIdentity = (s: BigIntStats): boolean => s.ino > 0n && s.dev >= 0n;

function safeSegments(value: string): string[] | null {
  if (value.length === 0 || value.length > 1024 || !/^[A-Za-z0-9_. /\\-]+$/.test(value)) return null;
  if (path.isAbsolute(value) || (process.platform !== "win32" && value.includes("\\"))) return null;
  const segments = value.split(/[\\/]/);
  if (segments.some((s) => !s || s === ".." || (s !== "." && s.endsWith(".")) || s.endsWith(" ") ||
    s.startsWith(" ") || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(s))) return null;
  return segments;
}

/** Research-only observation. Does not execute tools or make subsequent execution race-free. */
export class WorkspaceFileResolverV1 {
  private readonly root: string;
  private readonly workspaceId: string;
  private readonly aliases: ReadonlyMap<string, string>;
  private readonly rootIdentity: string | null;

  constructor(options: WorkspaceFileResolverOptionsV1) {
    if (!path.isAbsolute(options.rootDirectory) || !/^[A-Za-z0-9_.-]{1,128}$/.test(options.workspaceId)) {
      throw new Error("Invalid workspace resolver configuration");
    }
    this.root = path.resolve(options.rootDirectory);
    this.workspaceId = options.workspaceId;
    this.aliases = new Map(Object.entries(options.aliases ?? {}));
    try { this.rootIdentity = identity(this.inspectRoot()); } catch { this.rootIdentity = null; }
  }

  private inspectRoot(): BigIntStats {
    const base = path.parse(this.root).root;
    let current = base;
    let state = lstatSync(current, { bigint: true });
    if (state.isSymbolicLink() || !state.isDirectory()) throw new Error("root");
    for (const part of this.root.slice(base.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      state = lstatSync(current, { bigint: true });
      if (state.isSymbolicLink() || !state.isDirectory()) throw new Error("root");
    }
    if (!validIdentity(state)) throw new Error("identity");
    return state;
  }

  resolve(input: unknown): WorkspaceFileResolutionV1 {
    const parsed = WorkspaceFileRequestV1Schema.safeParse(input);
    if (!parsed.success) return unresolved("INVALID_INPUT");
    const { tool, arguments: args } = parsed.data;
    let effect: "READ" | "WRITE" | "DELETE";
    let relative: string;
    if (tool === "shell.command") {
      const shell = z.object({ command: z.string().max(MAX_BYTES + 2048) }).strict().safeParse(args);
      if (!shell.success) return unresolved("INVALID_INPUT");
      const match = /^(Get-Content|Set-Content|Remove-Item) -LiteralPath '([^'\r\n]+)'(?: -Value '([A-Za-z0-9_. ,!/?-]*)')?$/.exec(shell.data.command);
      if (!match || !match[2] || ((match[1] === "Set-Content") !== (match[3] !== undefined))) return unresolved("UNSUPPORTED_SYNTAX");
      effect = match[1] === "Get-Content" ? "READ" : match[1] === "Set-Content" ? "WRITE" : "DELETE";
      relative = match[2];
    } else {
      const match = /^(files|workspace)\.(read|write|delete)$/.exec(tool);
      if (!match) return unresolved("UNSUPPORTED_TOOL");
      effect = match[2] === "read" ? "READ" : match[2] === "write" ? "WRITE" : "DELETE";
      const value = z.string().min(1).max(1024);
      const schema = match[1] === "files" ? z.object({ path: value }) : z.object({ alias: value });
      const argumentsSchema = effect === "WRITE" ? schema.extend({ content: z.string().max(MAX_BYTES) }).strict() : schema.strict();
      const result = argumentsSchema.safeParse(args);
      if (!result.success) return unresolved("INVALID_INPUT");
      if ("path" in result.data) relative = result.data.path;
      else {
        const alias = this.aliases.get(result.data.alias);
        if (alias === undefined) return unresolved("UNKNOWN_ALIAS");
        relative = alias;
      }
    }
    const segments = safeSegments(relative);
    if (!segments) return unresolved("UNSAFE_PATH");
    try {
      if (this.rootIdentity === null || identity(this.inspectRoot()) !== this.rootIdentity) return unresolved("ROOT_UNAVAILABLE");
    } catch { return unresolved("ROOT_UNAVAILABLE"); }
    let descriptor: number | undefined;
    try {
      let current = this.root;
      const observations: { name: string; state: string }[] = [];
      for (const segment of segments) {
        current = path.join(current, segment);
        const state = lstatSync(current, { bigint: true });
        if (state.isSymbolicLink()) return unresolved("LINK_UNSUPPORTED");
        observations.push({ name: current, state: stamp(state) });
      }
      const target = lstatSync(current, { bigint: true });
      if (!target.isFile()) return unresolved("NOT_REGULAR_FILE");
      if (!validIdentity(target)) return unresolved("IDENTITY_UNAVAILABLE");
      if (target.nlink !== 1n) return unresolved("LINK_UNSUPPORTED");
      if (target.size > BigInt(MAX_BYTES)) return unresolved("FILE_TOO_LARGE");
      const canonical = realpathSync.native(current);
      const canonicalRelative = path.relative(realpathSync.native(this.root), canonical);
      if (!safeSegments(canonicalRelative)) return unresolved("UNSAFE_PATH");
      descriptor = openSync(current, constants.O_RDONLY | constants.O_NOFOLLOW);
      const opened = fstatSync(descriptor, { bigint: true });
      if (!opened.isFile() || stamp(opened) !== stamp(target)) return unresolved("STATE_CHANGED");
      const content = Buffer.alloc(MAX_BYTES + 1);
      let length = 0;
      while (length < content.length) {
        const count = readSync(descriptor, content, length, content.length - length, length);
        if (count === 0) break;
        length += count;
      }
      if (length > MAX_BYTES) return unresolved("FILE_TOO_LARGE");
      if (BigInt(length) !== opened.size || stamp(fstatSync(descriptor, { bigint: true })) !== stamp(opened) ||
        observations.some((o) => stamp(lstatSync(o.name, { bigint: true })) !== o.state) ||
        identity(this.inspectRoot()) !== this.rootIdentity || realpathSync.native(current) !== canonical) return unresolved("STATE_CHANGED");
      return { schemaVersion: "1.0.0", status: "RESOLVED", effect,
        resource: { resourceId: `file:${hash(JSON.stringify([this.workspaceId, opened.dev.toString(), opened.ino.toString()]))}`,
          relativePath: canonicalRelative.split(path.sep).join("/"),
          stateDigest: `sha256:${hash(JSON.stringify([stamp(opened), hash(content.subarray(0, length))]))}` }, reason: null };
    } catch { return unresolved("FILESYSTEM_UNAVAILABLE"); }
    finally { if (descriptor !== undefined) closeSync(descriptor); }
  }
}
