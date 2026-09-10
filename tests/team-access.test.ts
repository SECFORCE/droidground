import assert from "node:assert/strict";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { ManagerSingleton, TeamAccessError } from "../src/server/manager";
import { CompanionClient } from "../src/server/companion";
import APIController from "../src/server/api/controller";
import { FairQueue } from "../src/server/utils/queue";
import Logger from "../src/shared/logger";

const teamA = "test-team-a-token";
const teamB = "test-team-b-token";
const packageName = "com.example.teamapp";
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

function managerFixture(t: TestContext) {
  t.mock.method(Logger, "info", () => {});
  t.mock.method(Logger, "debug", () => {});
  t.mock.method(Logger, "error", () => {});
  const env = {
    DROIDGROUND_NUM_TEAMS: "2",
    DROIDGROUND_TEAM_TOKEN_1: teamA,
    DROIDGROUND_TEAM_TOKEN_2: teamB,
    DROIDGROUND_IP_STATIC: "127.0.0.1",
    DROIDGROUND_APP_PACKAGE_NAME: "com.example.target",
  };
  const original = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
  Object.assign(process.env, env);
  t.after(() => {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const manager = Reflect.construct(ManagerSingleton, []) as ManagerSingleton;
  t.after(() => rmSync(manager.getTmpDir(), { recursive: true, force: true }));
  t.mock.method(ManagerSingleton, "getInstance", () => manager);
  return manager;
}

function response() {
  return {
    code: 200,
    body: undefined as any,
    status(code: number) {
      this.code = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    end() {
      return this;
    },
  };
}

function denied(status: number) {
  return (error: unknown) => error instanceof TeamAccessError && error.status === status;
}

test("tokens must be valid strings and authorize only their exclusively owned app", t => {
  const manager = managerFixture(t);
  manager.registerInstalledApp(packageName, teamA);
  for (const token of [undefined, null, "", "unknown", 5, [teamA], { token: teamA }]) {
    assert.equal(manager.isTeamTokenValid(token), false);
    assert.throws(() => manager.assertAppAccess(packageName, token as any), denied(401));
  }
  assert.doesNotThrow(() => manager.assertAppAccess(packageName, teamA));
  assert.throws(() => manager.assertAppAccess(packageName, teamB), denied(403));
  assert.throws(() => manager.assertAppAccess("com.example.unregistered", teamA), denied(403));
  // Reject ambiguous ownership left behind by older versions as well.
  manager.getConfig().teams[1].exploitApps.push(packageName);
  assert.throws(() => manager.assertAppAccess(packageName, teamA), denied(403));
});

test("duplicate configured tokens cannot create teams with indistinguishable identities", t => {
  managerFixture(t);
  process.env.DROIDGROUND_TEAM_TOKEN_2 = teamA;
  assert.throws(() => Reflect.construct(ManagerSingleton, []), /unique Team Token/);
});

test("package reservations exclude other installations and cannot unlock a newer reservation", t => {
  const manager = managerFixture(t);
  const release = manager.reserveAppInstallation(packageName, teamA);
  assert.throws(() => manager.reserveAppInstallation(packageName, teamB), denied(409));
  release();
  const releaseNext = manager.reserveAppInstallation(packageName, teamB);
  release();
  assert.throws(() => manager.reserveAppInstallation(packageName, teamA), denied(409));
  releaseNext();
  manager.registerInstalledApp(packageName, teamA);
  assert.throws(() => manager.reserveAppInstallation(packageName, teamB), denied(403));
  assert.throws(() => manager.reserveAppInstallation(manager.getConfig().packageName, teamA), denied(403));
});

test("invalid and cross-team requests are denied before reaching the queue", async t => {
  const manager = managerFixture(t);
  manager.registerInstalledApp(packageName, teamA);
  const enqueue = t.mock.method(manager.queue, "enqueue", () => {
    throw new Error("Queue must not be reached");
  });
  for (const [token, status] of [
    [undefined, 401],
    ["unknown", 401],
    [teamB, 403],
  ] as const) {
    const res = response();
    await APIController.enqueueStartExploitApp(
      { body: { packageName, teamToken: token } } as any,
      res as any,
      () => {},
    );
    assert.equal(res.code, status);
    assert.equal(JSON.stringify(res.body).includes(String(token)), false);
  }
  assert.equal(enqueue.mock.callCount(), 0);
});

test("authorization is rechecked when a queued job's ownership has been revoked", async t => {
  const manager = managerFixture(t);
  manager.registerInstalledApp(packageName, teamA);
  let job: any;
  t.mock.method(manager.queue, "enqueue", input => {
    job = input;
    return { ok: true, createdAt: 1 };
  });
  const launch = t.mock.method(APIController, "startExploitApp", async () => {
    throw new Error("Must not launch");
  });
  const res = response();
  await APIController.enqueueStartExploitApp({ body: { packageName, teamToken: teamA } } as any, res as any, () => {});
  assert.equal(res.code, 202);
  manager.getConfig().teams[0].exploitApps = [];
  await assert.rejects(job.run(1), denied(403));
  assert.equal(launch.mock.callCount(), 0);
});

function installationFixture(t: TestContext, manager: ManagerSingleton, result = "Failure") {
  const sync = { write: async () => {}, dispose: async () => {} };
  const install = t.mock.fn(async () => result);
  const cleanup = t.mock.fn(async () => {});
  t.mock.method(
    manager,
    "getAdb",
    async () =>
      ({
        sync: async () => sync,
        rm: cleanup,
        subprocess: { noneProtocol: { spawnWaitText: install } },
      }) as any,
  );
  t.mock.method(CompanionClient, "getInstance", () => ({ sendMessage: async () => ({ packageName }) }) as any);
  let id = 0;
  const request = (teamToken: string) => {
    const filename = `test-upload-${++id}`;
    const filePath = path.join(manager.getTmpDir(), filename);
    writeFileSync(filePath, "inert test data");
    return { body: { teamToken }, file: { path: filePath, filename, size: 15 } };
  };
  return { request, install, cleanup };
}

test("a rejected token cannot touch the device and its temporary upload is removed", async t => {
  const manager = managerFixture(t);
  const { request } = installationFixture(t, manager);
  const getAdb = t.mock.method(manager, "getAdb", async () => {
    throw new Error("Device must not be reached");
  });
  const req = request("unknown");
  const res = response();
  await APIController.apk(req as any, res as any, () => {});
  assert.equal(res.code, 401);
  assert.equal(getAdb.mock.callCount(), 0);
  assert.equal(existsSync(req.file.path), false);
});

test("a failed installation never grants ownership or app access", async t => {
  const manager = managerFixture(t);
  const { request } = installationFixture(t, manager);
  const req = request(teamA);
  const res = response();
  await APIController.apk(req as any, res as any, () => {});
  assert.equal(res.code, 500);
  assert.deepEqual(manager.getExploitAppsLinkedToTeam(teamA), []);
  assert.deepEqual(manager.exploitApps, []);
  assert.throws(() => manager.assertAppAccess(packageName, teamA), denied(403));
  assert.equal(existsSync(req.file.path), false);
  // A failed attempt must also relinquish its temporary package reservation.
  manager.reserveAppInstallation(packageName, teamB)();
});

test("another team cannot install over an owned package or change its ownership", async t => {
  const manager = managerFixture(t);
  manager.registerInstalledApp(packageName, teamA);
  const { request, install } = installationFixture(t, manager, "Success");
  const res = response();
  await APIController.apk(request(teamB) as any, res as any, () => {});
  assert.equal(res.code, 403);
  assert.equal(install.mock.callCount(), 0);
  assert.deepEqual(manager.getExploitAppsLinkedToTeam(teamB), []);
  assert.deepEqual(manager.getExploitAppsLinkedToTeam(teamA), [packageName]);
});

test("ownership is committed only after a confirmed successful installation", async t => {
  const manager = managerFixture(t);
  const { request, install } = installationFixture(t, manager, "Success");
  install.mock.mockImplementation(async () => {
    assert.deepEqual(manager.getExploitAppsLinkedToTeam(teamA), []);
    assert.deepEqual(manager.exploitApps, []);
    return "Success";
  });
  const res = response();
  await APIController.apk(request(teamA) as any, res as any, () => {});
  assert.equal(res.code, 200);
  assert.deepEqual(manager.getExploitAppsLinkedToTeam(teamA), [packageName]);
  assert.throws(() => manager.assertAppAccess(packageName, teamB), denied(403));
});

test("queue logs never include team credentials", async t => {
  const lines: string[] = [];
  t.mock.method(Logger, "info", message => lines.push(String(message)));
  t.mock.method(Logger, "error", message => lines.push(String(message)));
  const queue = new FairQueue({ concurrency: 1, maxPerUserQueue: 1, maxTotalQueue: 2 });
  queue.enqueue({ id: "test-job", userId: teamA, packageName, run: async () => {} });
  await tick();
  assert.equal(lines.length, 3);
  assert.equal(
    lines.some(line => line.includes(teamA)),
    false,
  );
});
