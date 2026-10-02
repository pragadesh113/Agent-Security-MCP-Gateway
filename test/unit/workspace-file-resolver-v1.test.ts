import { mkdtempSync, mkdirSync, writeFileSync, rmSync, linkSync, symlinkSync, renameSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WorkspaceFileResolverV1, WorkspaceFileResolutionV1Schema } from "../../src/action-normalizer/workspace-file-resolver-v1.js";

describe("research workspace file resolver", () => {
  let base: string;
  let root: string;
  let resolver: WorkspaceFileResolverV1;
  const call = (tool: string, args: unknown) => resolver.resolve({ schemaVersion: "1.0.0", tool, arguments: args });
  beforeEach(() => {
    base = mkdtempSync(path.join(tmpdir(), "resolver-unit-"));
    root = path.join(base, "workspace");
    mkdirSync(path.join(root, "docs"), { recursive: true });
    writeFileSync(path.join(root, "docs", "sample.txt"), "fixture contents");
    resolver = new WorkspaceFileResolverV1({ rootDirectory: root, workspaceId: "test-workspace", aliases: { sample: "docs/sample.txt", escape: "../outside.txt" } });
  });
  afterEach(() => { rmSync(base, { recursive: true, force: true }); });

  it.each([
    ["read", "READ", "Get-Content -LiteralPath 'docs/sample.txt'"],
    ["write", "WRITE", "Set-Content -LiteralPath 'docs/sample.txt' -Value 'new value'"],
    ["delete", "DELETE", "Remove-Item -LiteralPath 'docs/sample.txt'"]
  ])("observes equivalent %s identities without executing an effect", (operation, effect, command) => {
    const extra = operation === "write" ? { content: "new value" } : {};
    const direct = call(`files.${operation}`, { path: "docs/sample.txt", ...extra });
    const alias = call(`workspace.${operation}`, { alias: "sample", ...extra });
    const shell = call("shell.command", { command });
    expect(direct.status).toBe("RESOLVED");
    expect(direct.effect).toBe(effect);
    expect(alias).toEqual(direct);
    expect(shell).toEqual(direct);
    expect(WorkspaceFileResolutionV1Schema.safeParse(direct).success).toBe(true);
    expect(readFileSync(path.join(root, "docs", "sample.txt"), "utf8")).toBe("fixture contents");
    expect(JSON.stringify(direct)).not.toContain(root);
    expect(JSON.stringify(direct)).not.toContain("fixture contents");
  });

  it.each(["../outside.txt", "docs/../docs/sample.txt", "/docs/sample.txt", "C:\\docs\\sample.txt", "\\\\server\\share\\file", "\\\\?\\C:\\file", "docs/sample.txt:stream", "docs/*.txt", "docs/%73ample.txt", "docs/sample.txt.", "docs/sample.txt ", "docs/con.txt", "docs/LPT1", "docs//sample.txt", "docs/sa`mple.txt", "docs/sa$mple.txt", "docs/é.txt", "docs/sa\nmple.txt", "docs/short~1.txt"])("rejects unsafe path %s", (candidate) => {
    expect(call("files.read", { path: candidate })).toMatchObject({ status: "UNRESOLVED", effect: "UNKNOWN", resource: null });
  });
  it("resolves dot segments after inspecting every preceding directory", () => {
    expect(call("files.read", { path: "./docs/./sample.txt" })).toEqual(call("files.read", { path: "docs/sample.txt" }));
  });
  it.each([
    "Get-Content 'docs/sample.txt'", "get-content -LiteralPath 'docs/sample.txt'", "Get-Content -LiteralPath \"docs/sample.txt\"",
    "Get-Content -LiteralPath 'docs/sample.txt'; Remove-Item x", "Get-Content -LiteralPath 'docs/sample.txt' | Out-String",
    "Set-Content -LiteralPath 'docs/sample.txt'", "Remove-Item -LiteralPath 'docs/sample.txt' -Recurse",
    "Get-Content -LiteralPath 'docs/sample.txt' -Value 'x'", "Set-Content -LiteralPath 'docs/sample.txt' -Value '$(evil)'"
  ])("rejects unsupported shell syntax %s", (command) => { expect(call("shell.command", { command }).status).toBe("UNRESOLVED"); });

  it("rejects schema drift and unsupported operations", () => {
    for (const input of [null, {}, { schemaVersion: "2.0.0", tool: "files.read", arguments: { path: "docs/sample.txt" } },
      { schemaVersion: "1.0.0", tool: "files.read", arguments: { path: "docs/sample.txt" }, effect: "READ" }]) {
      expect(resolver.resolve(input).status).toBe("UNRESOLVED");
    }
    expect(call("files.move", { path: "docs/sample.txt" }).reason).toBe("UNSUPPORTED_TOOL");
    expect(call("files.write", { path: "docs/sample.txt" }).reason).toBe("INVALID_INPUT");
    expect(call("files.read", { path: "docs/sample.txt", approved: true }).reason).toBe("INVALID_INPUT");
    expect(call("workspace.read", { alias: "missing" }).reason).toBe("UNKNOWN_ALIAS");
    expect(call("workspace.read", { alias: "escape" }).reason).toBe("UNSAFE_PATH");
    expect(call("files.read", { path: "docs" }).reason).toBe("NOT_REGULAR_FILE");
    expect(call("files.read", { path: "absent.txt" }).reason).toBe("FILESYSTEM_UNAVAILABLE");
  });

  it("binds fresh content state and scopes identities to the workspace", () => {
    const before = call("files.read", { path: "docs/sample.txt" });
    writeFileSync(path.join(root, "docs", "sample.txt"), "changed contents");
    const after = call("files.read", { path: "docs/sample.txt" });
    expect(before.resource?.resourceId).toBe(after.resource?.resourceId);
    expect(before.resource?.stateDigest).not.toBe(after.resource?.stateDigest);
    const other = new WorkspaceFileResolverV1({ rootDirectory: root, workspaceId: "other" });
    expect(other.resolve({ schemaVersion: "1.0.0", tool: "files.read", arguments: { path: "docs/sample.txt" } }).resource?.resourceId).not.toBe(after.resource?.resourceId);
  });

  it("rejects hardlinked files and oversized files", () => {
    linkSync(path.join(root, "docs", "sample.txt"), path.join(root, "linked.txt"));
    expect(call("files.read", { path: "docs/sample.txt" }).reason).toBe("LINK_UNSUPPORTED");
    writeFileSync(path.join(root, "large.txt"), Buffer.alloc(1024 * 1024 + 1));
    expect(call("files.read", { path: "large.txt" }).reason).toBe("FILE_TOO_LARGE");
  });

  it("rejects directory links before any lexical traversal reduction", () => {
    const outside = path.join(base, "outside");
    mkdirSync(outside);
    writeFileSync(path.join(outside, "sample.txt"), "outside fixture");
    symlinkSync(outside, path.join(root, "jump"), process.platform === "win32" ? "junction" : "dir");
    expect(call("files.read", { path: "jump/sample.txt" }).reason).toBe("LINK_UNSUPPORTED");
    expect(call("files.read", { path: "jump/../docs/sample.txt" }).reason).toBe("UNSAFE_PATH");
    const linkedRoot = new WorkspaceFileResolverV1({ rootDirectory: path.join(root, "jump"), workspaceId: "linked" });
    expect(linkedRoot.resolve({ schemaVersion: "1.0.0", tool: "files.read", arguments: { path: "sample.txt" } }).reason).toBe("ROOT_UNAVAILABLE");
  });

  it("does not follow a root replaced after construction", () => {
    renameSync(root, path.join(base, "old"));
    mkdirSync(root);
    writeFileSync(path.join(root, "sample.txt"), "replacement");
    expect(call("files.read", { path: "sample.txt" }).reason).toBe("ROOT_UNAVAILABLE");
  });

  it("keeps an initially unavailable root unresolved", () => {
    const unavailable = new WorkspaceFileResolverV1({ rootDirectory: path.join(base, "missing"), workspaceId: "missing" });
    expect(unavailable.resolve({ schemaVersion: "1.0.0", tool: "files.read", arguments: { path: "file.txt" } }).reason).toBe("ROOT_UNAVAILABLE");
  });
});
