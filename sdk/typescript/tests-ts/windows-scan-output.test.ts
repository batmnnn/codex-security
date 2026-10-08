import { execFile } from "node:child_process";
import {
  cp,
  lstat,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, expect, mock, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { runMultiscan } from "../src/multiscan.js";
import * as runtime from "../src/runtime.js";
import { fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { gitText } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-output-acl-",
);
afterEach(cleanup);
const exec = promisify(execFile);
const windowsTest = test.skipIf(process.platform !== "win32");
const example = join(PLUGIN_ROOT, "examples", "completed-scan");

async function icacls(path: string, ...args: string[]): Promise<void> {
  await exec(
    join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "icacls.exe"),
    [path, ...args],
  );
}

async function descriptor(path: string): Promise<string> {
  const system = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
  const result = await exec(
    join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$ErrorActionPreference = 'Stop'; Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
    ],
    {
      env: {
        ...process.env,
        CODEX_SECURITY_TEST_ACL_PATH: path,
        PSModulePath: join(system, "WindowsPowerShell", "v1.0", "Modules"),
      },
    },
  );
  return result.stdout.trim();
}

windowsTest(
  "new Windows scan roots start private beneath a shared parent",
  async () => {
    const root = await temporaryDirectory();
    await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
    const before = await descriptor(root);
    expect(before).toContain(";;;WD)");
    const explicit = join(root, "new parent", "scan");
    expect(await runtime.prepareOutputDir(explicit, "fixture")).toBe(
      await realpath(explicit),
    );
    const generated = await runtime.prepareOutputDir(
      undefined,
      "fixture",
      root,
    );
    for (const output of [join(root, "new parent"), explicit, generated]) {
      const acl = await descriptor(output);
      expect(acl).toContain("D:P");
      expect(acl).not.toContain(";;;WD)");
    }
    expect(await descriptor(root)).toBe(before);
  },
);

windowsTest.each([204, 233])(
  "generated Windows output supports a %i-character repository name",
  async (length) => {
    const root = await temporaryDirectory();
    await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
    const output = await runtime.prepareOutputDir(
      undefined,
      "r".repeat(length),
      root,
    );
    expect((await lstat(output)).isDirectory()).toBe(true);
    expect(basename(output).length).toBeLessThanOrEqual(255);
    expect(basename(output)).toMatch(
      /-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    const acl = await descriptor(output);
    expect(acl).toContain("D:P");
    expect(acl).not.toContain(";;;WD)");
  },
);

windowsTest(
  "existing Windows scan ACLs and native sandbox grants are preserved",
  async () => {
    const root = await temporaryDirectory();
    const output = join(root, "scan");
    await mkdir(output);
    // Synthetic capability-format SID: verify preservation, not native sandbox identity.
    const capability = "S-1-5-21-444-555-666-777";
    await icacls(output, "/grant", `*${capability}:(OI)(CI)M`);
    const before = await descriptor(output);
    expect(before).toContain(capability);
    expect(await runtime.prepareOutputDir(output, "fixture")).toBe(
      await realpath(output),
    );
    expect(await descriptor(output)).toBe(before);
    await cp(example, output, { recursive: true });
    expect(
      await runtime.prepareScanRegistrationOutput(
        output,
        "fixture",
        root,
        undefined,
        true,
      ),
    ).toBe(await realpath(output));
    await loadContract(output, { pluginRoot: PLUGIN_ROOT });
    expect(await descriptor(output)).toBe(before);
  },
);

windowsTest(
  "archiving Windows output preserves old ACLs and privately creates the replacement",
  async () => {
    const root = await temporaryDirectory();
    await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
    const output = join(root, "scan");
    await mkdir(output);
    await writeFile(join(output, "retained.txt"), "Synthetic retained data");
    const original = await descriptor(output);
    let archive: string | undefined;
    await runtime.prepareOutputDir(
      output,
      "fixture",
      root,
      undefined,
      true,
      (path) => {
        archive = path;
      },
    );
    expect(archive).toBeDefined();
    expect(await descriptor(archive!)).toBe(original);
    expect(await readFile(join(archive!, "retained.txt"), "utf8")).toBe(
      "Synthetic retained data",
    );
    expect(await descriptor(output)).not.toContain(";;;WD)");
  },
);

windowsTest(
  "new Windows output creation accepts parent aliases and leaves rejected locations absent",
  async () => {
    const root = await temporaryDirectory();
    const destination = join(root, "destination");
    const alias = join(root, "alias");
    await mkdir(destination);
    await symlink(destination, alias, "junction");
    const prepared = await runtime.prepareOutputDir(
      join(alias, "scan"),
      "fixture",
    );
    expect(prepared).toBe(await realpath(join(destination, "scan")));
    const rejected = join(alias, "rejected");
    const failure = new Error("Synthetic rejected location");
    await expect(
      runtime.prepareOutputDir(rejected, "fixture", root, () => {
        throw failure;
      }),
    ).rejects.toBe(failure);
    await expect(lstat(rejected)).rejects.toMatchObject({ code: "ENOENT" });
  },
);

windowsTest(
  "Windows campaigns preserve legitimate checkout links and protect their ledger",
  async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    gitText(["init", "-q", repository]);
    await writeFile(join(repository, "fixture.txt"), "Synthetic repository\n");
    gitText(["-C", repository, "add", "."]);
    gitText([
      "-C",
      repository,
      "-c",
      "user.name=Synthetic Author",
      "-c",
      "user.email=author@example.test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-qm",
      "Synthetic fixture",
    ]);
    const revision = gitText(["-C", repository, "rev-parse", "HEAD"]).trim();
    const input = join(root, "repositories.csv");
    await writeFile(
      input,
      `id,repository,revision\nrepo,${repository},${revision}\n`,
    );
    await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
    const output = join(root, "campaign");
    const run = mock(
      async (_repository: string, scan: { outputDir?: string } = {}) => {
        await cp(example, scan.outputDir!, { recursive: true });
        return fakeResult();
      },
    );
    const options = {
      inputPath: input,
      outputDir: output,
      workers: 1,
      mode: "standard" as const,
      maxAttempts: 1,
      config: {},
      createSecurity: () => ({ run, close: async () => {} }),
    };
    const initial = await runMultiscan(options);
    const ledger = await readFile(initial.resultsPath);
    expect(await descriptor(initial.resultsPath)).not.toContain(";;;WD)");
    const checkout = join(output, "checkouts", "retained");
    await mkdir(checkout);
    const outside = join(root, "external-data");
    await mkdir(outside);
    await symlink(outside, join(checkout, "linked-directory"), "junction");
    const unrelated = join(checkout, "unrelated.txt");
    await writeFile(unrelated, "Synthetic checkout data\n");
    await icacls(unrelated, "/grant", "*S-1-1-0:R");
    const original = await descriptor(unrelated);
    expect(await runMultiscan(options)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(
      (await lstat(join(checkout, "linked-directory"))).isSymbolicLink(),
    ).toBe(true);
    expect(await descriptor(unrelated)).toBe(original);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    await icacls(initial.resultsPath, "/grant", "*S-1-1-0:R");
    const unsafe = await descriptor(initial.resultsPath);
    expect(await runMultiscan(options)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await descriptor(initial.resultsPath)).toBe(unsafe);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
  },
);
