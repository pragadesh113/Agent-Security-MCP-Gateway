import { createHash } from "node:crypto";
import {
  existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  renameSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { WorkspaceFileResolverV1 } from "../../src/action-normalizer/workspace-file-resolver-v1.js";

function cleanupWorkspace(root: string, temporaryParent: string): void {
  // Only the exact directory created by the fixture is eligible for recursive cleanup.
  const cleanupRoot = resolve(root);
  if (dirname(cleanupRoot) !== temporaryParent
    || !basename(cleanupRoot).startsWith("resolver-integration-")
    || cleanupRoot === temporaryParent) {
    throw new Error("Refusing cleanup outside the disposable fixture boundary");
  }
  rmSync(cleanupRoot, { recursive: true, force: true });
}

function withWorkspace(run: (root: string) => void): void {
  const temporaryParent = resolve(tmpdir());
  const root = mkdtempSync(join(temporaryParent, "resolver-integration-"));
  try {
    run(root);
  } finally {
    cleanupWorkspace(root, temporaryParent);
  }
}

function request(tool: string, arguments_: Record<string, unknown>) {
  return { schemaVersion: "1.0.0" as const, tool, arguments: arguments_ };
}

function observedIdentity(path: string): string {
  const observation = statSync(path, { bigint: true });
  return `${observation.dev.toString()}:${observation.ino.toString()}`;
}

describe("workspace resolver against disposable filesystem observations", () => {
  it("identifies equivalent direct, alias, and shell reads without changing the resource", () => {
    withWorkspace((root) => {
      mkdirSync(join(root, "notes"));
      const path = join(root, "notes", "record.txt");
      writeFileSync(path, "fixture content", "utf8");
      const resolver = new WorkspaceFileResolverV1({
        rootDirectory: root, workspaceId: "integration-workspace", aliases: { current: "notes/record.txt" }
      });
      const beforeIdentity = observedIdentity(path);
      const observed = statSync(path, { bigint: true });
      const expectedResourceId = `file:${createHash("sha256").update(JSON.stringify([
        "integration-workspace", observed.dev.toString(), observed.ino.toString()
      ])).digest("hex")}`;
      const variants = [
        request("files.read", { path: "notes/record.txt" }),
        request("files.read", { path: "./notes/record.txt" }),
        request("workspace.read", { alias: "current" }),
        request("shell.command", { command: "Get-Content -LiteralPath 'notes/record.txt'" })
      ];
      const results = variants.map((variant) => resolver.resolve(variant));
      for (const result of results) {
        expect(result).toMatchObject({ status: "RESOLVED", effect: "READ", reason: null });
        expect(result.resource?.relativePath).toBe("notes/record.txt");
        expect(result.resource?.resourceId).toBe(expectedResourceId);
        expect(result.resource?.resourceId).toBe(results[0]?.resource?.resourceId);
        expect(result.resource?.stateDigest).toBe(results[0]?.resource?.stateDigest);
        expect(JSON.stringify(result)).not.toContain(root);
        expect(JSON.stringify(result)).not.toContain(JSON.stringify(root).slice(1, -1));
        expect(JSON.stringify(result)).not.toContain(root.replaceAll("\\", "/"));
      }
      expect(readFileSync(path, "utf8")).toBe("fixture content");
      expect(observedIdentity(path)).toBe(beforeIdentity);
    });
  });

  it("observes actual read, write, and delete effects independently of resolver predictions", () => {
    withWorkspace((root) => {
      const path = join(root, "record.txt");
      writeFileSync(path, "before", "utf8");
      const resolver = new WorkspaceFileResolverV1({ rootDirectory: root, workspaceId: "integration-workspace" });
      const before = resolver.resolve(request("files.read", { path: "record.txt" }));
      expect(before.status).toBe("RESOLVED");
      const identityBefore = observedIdentity(path);
      expect(readFileSync(path, "utf8")).toBe("before");

      const proposedWrite = resolver.resolve(request("files.write", { path: "record.txt", content: "after!" }));
      expect(proposedWrite).toMatchObject({ status: "RESOLVED", effect: "WRITE", resource: before.resource });
      expect(readFileSync(path, "utf8")).toBe("before");
      writeFileSync(path, "after!", "utf8");
      expect(observedIdentity(path)).toBe(identityBefore);
      const afterWrite = resolver.resolve(request("files.read", { path: "record.txt" }));
      expect(afterWrite.status).toBe("RESOLVED");
      expect(afterWrite.resource?.resourceId).toBe(before.resource?.resourceId);
      expect(afterWrite.resource?.stateDigest).not.toBe(before.resource?.stateDigest);
      expect(readFileSync(path, "utf8")).toBe("after!");

      const proposedDelete = resolver.resolve(request("files.delete", { path: "record.txt" }));
      expect(proposedDelete).toMatchObject({ status: "RESOLVED", effect: "DELETE", resource: afterWrite.resource });
      expect(existsSync(path)).toBe(true);
      unlinkSync(path);
      expect(existsSync(path)).toBe(false);
      expect(resolver.resolve(request("files.read", { path: "record.txt" }))).toMatchObject({
        status: "UNRESOLVED", effect: "UNKNOWN", resource: null
      });
    });
  });

  it("detects alias retargeting and replacement at the same path", () => {
    withWorkspace((root) => {
      const firstPath = join(root, "first.txt");
      const secondPath = join(root, "second.txt");
      writeFileSync(firstPath, "identical content", "utf8");
      writeFileSync(secondPath, "identical content", "utf8");
      expect(observedIdentity(firstPath)).not.toBe(observedIdentity(secondPath));
      const firstResolver = new WorkspaceFileResolverV1({
        rootDirectory: root, workspaceId: "integration-workspace", aliases: { current: "first.txt" }
      });
      const retargetedResolver = new WorkspaceFileResolverV1({
        rootDirectory: root, workspaceId: "integration-workspace", aliases: { current: "second.txt" }
      });
      const aliasRequest = request("workspace.read", { alias: "current" });
      const first = firstResolver.resolve(aliasRequest);
      const retargeted = retargetedResolver.resolve(aliasRequest);
      expect(first.status).toBe("RESOLVED");
      expect(retargeted.status).toBe("RESOLVED");
      expect(first.resource?.resourceId).not.toBe(retargeted.resource?.resourceId);

      // Both files coexist before replacement, preventing inode reuse from obscuring this test.
      unlinkSync(firstPath);
      renameSync(secondPath, firstPath);
      const replacement = firstResolver.resolve(aliasRequest);
      expect(replacement.status).toBe("RESOLVED");
      expect(replacement.resource?.resourceId).not.toBe(first.resource?.resourceId);
      expect(replacement.resource?.stateDigest).not.toBe(first.resource?.stateDigest);
    });
  });

  it("resolves alias and shell mutations without executing them", () => {
    withWorkspace((root) => {
      const path = join(root, "record.txt");
      writeFileSync(path, "unchanged", "utf8");
      const resolver = new WorkspaceFileResolverV1({
        rootDirectory: root, workspaceId: "integration-workspace", aliases: { current: "record.txt" }
      });
      const before = resolver.resolve(request("files.read", { path: "record.txt" }));
      expect(before.status).toBe("RESOLVED");
      const mutations = [
        { effect: "WRITE", call: request("workspace.write", { alias: "current", content: "changed" }) },
        { effect: "WRITE", call: request("shell.command", { command: "Set-Content -LiteralPath 'record.txt' -Value 'changed'" }) },
        { effect: "DELETE", call: request("workspace.delete", { alias: "current" }) },
        { effect: "DELETE", call: request("shell.command", { command: "Remove-Item -LiteralPath 'record.txt'" }) }
      ];
      for (const mutation of mutations) {
        expect(resolver.resolve(mutation.call)).toMatchObject({
          status: "RESOLVED", effect: mutation.effect, resource: before.resource, reason: null
        });
        expect(readFileSync(path, "utf8")).toBe("unchanged");
      }
      expect(resolver.resolve(request("shell.command", {
        command: "Get-Content -LiteralPath 'record.txt'; Remove-Item -LiteralPath 'record.txt'"
      }))).toMatchObject({ status: "UNRESOLVED", effect: "UNKNOWN", resource: null });
      expect(readFileSync(path, "utf8")).toBe("unchanged");
    });
  });

  it("denies real linked ancestors and traversal through them", () => {
    withWorkspace((root) => {
      const workspace = join(root, "workspace");
      const outside = join(root, "outside");
      mkdirSync(workspace);
      mkdirSync(outside);
      writeFileSync(join(outside, "private.txt"), "outside fixture", "utf8");
      writeFileSync(join(workspace, "target.txt"), "inside fixture", "utf8");
      const link = join(workspace, "linked");
      symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
      expect(lstatSync(link).isSymbolicLink()).toBe(true);
      const resolver = new WorkspaceFileResolverV1({ rootDirectory: workspace, workspaceId: "integration-workspace" });
      for (const path of ["linked/private.txt", "linked/../target.txt"]) {
        const result = resolver.resolve(request("files.read", { path }));
        expect(result).toMatchObject({ status: "UNRESOLVED", effect: "UNKNOWN", resource: null });
        expect(JSON.stringify(result)).not.toContain(root);
        expect(JSON.stringify(result)).not.toContain(JSON.stringify(root).slice(1, -1));
        expect(JSON.stringify(result)).not.toContain("outside fixture");
      }
      expect(readFileSync(join(outside, "private.txt"), "utf8")).toBe("outside fixture");
    });
  });

  it("denies both names of a real hardlinked file", () => {
    withWorkspace((root) => {
      const original = join(root, "original.txt");
      const linked = join(root, "linked.txt");
      writeFileSync(original, "hardlink fixture", "utf8");
      linkSync(original, linked);
      expect(observedIdentity(original)).toBe(observedIdentity(linked));
      expect(statSync(original).nlink).toBeGreaterThan(1);
      const resolver = new WorkspaceFileResolverV1({ rootDirectory: root, workspaceId: "integration-workspace" });
      for (const path of ["original.txt", "linked.txt"]) {
        expect(resolver.resolve(request("files.delete", { path }))).toMatchObject({
          status: "UNRESOLVED", effect: "UNKNOWN", resource: null
        });
      }
      expect(readFileSync(original, "utf8")).toBe("hardlink fixture");
      expect(readFileSync(linked, "utf8")).toBe("hardlink fixture");
    });
  });

  it("denies directories, missing files, and absent intermediate directories", () => {
    withWorkspace((root) => {
      mkdirSync(join(root, "directory"));
      const resolver = new WorkspaceFileResolverV1({ rootDirectory: root, workspaceId: "integration-workspace" });
      for (const path of ["directory", "missing.txt", "absent/record.txt"]) {
        expect(resolver.resolve(request("files.write", { path, content: "must not create" }))).toMatchObject({
          status: "UNRESOLVED", effect: "UNKNOWN", resource: null
        });
      }
      expect(existsSync(join(root, "missing.txt"))).toBe(false);
      expect(existsSync(join(root, "absent"))).toBe(false);
    });
  });

  it("rejects a replaced workspace root even when the relative file still exists", () => {
    withWorkspace((root) => {
      const workspace = join(root, "workspace");
      mkdirSync(workspace);
      writeFileSync(join(workspace, "record.txt"), "original", "utf8");
      const resolver = new WorkspaceFileResolverV1({ rootDirectory: workspace, workspaceId: "integration-workspace" });
      const read = request("files.read", { path: "record.txt" });
      expect(resolver.resolve(read).status).toBe("RESOLVED");
      renameSync(workspace, join(root, "retired"));
      mkdirSync(workspace);
      writeFileSync(join(workspace, "record.txt"), "substituted", "utf8");
      expect(resolver.resolve(read)).toMatchObject({ status: "UNRESOLVED", effect: "UNKNOWN", resource: null });
    });
  });
});
