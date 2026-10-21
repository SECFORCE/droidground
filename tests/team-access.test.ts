import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { ManagerSingleton, TeamAccessError } from "../src/server/manager";
import { CompanionClient } from "../src/server/companion";
import APIController from "../src/server/api/controller";
import { FairQueue } from "../src/server/utils/queue";
import Logger from "../src/shared/logger";
import { WebSocket } from "ws";
import { ScrcpyVideoCodecId } from "@yume-chan/scrcpy";
import { setupScrcpyWss } from "../src/server/ws/scrcpy";
import { broadcastForPhase } from "../src/server/utils/ws";
import { parseVideoMessage } from "../src/client/utils/video-stream";
import { StreamingPhase, WSMessageType } from "../src/shared/types";

const teamA = "test-team-a-token";
const teamB = "test-team-b-token";
const packageName = "com.example.teamapp";
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

function managerFixture(t: TestContext, teams = "2") {
  t.mock.method(Logger, "info", () => {});
  t.mock.method(Logger, "debug", () => {});
  t.mock.method(Logger, "error", () => {});
  const env = {
    DROIDGROUND_NUM_TEAMS: teams,
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

function streamingFixture(manager: ManagerSingleton) {
  const data = new Uint8Array([0, 0, 0, 1, 0x65]);
  manager.sharedVideoMetadata = {
    codec: ScrcpyVideoCodecId.H264,
    width: 100,
    height: 200,
    videoEncoder: "test",
    hardwareType: "software",
  };
  manager.sharedConfiguration = { type: "configuration", data };
  const wss = new EventEmitter();
  setupScrcpyWss(wss as any);
  const connect = () => {
    const messages: ReturnType<typeof parseVideoMessage>[] = [];
    const ws = Object.assign(new EventEmitter(), {
      readyState: WebSocket.OPEN,
      bufferedAmount: 0,
      send: (payload: Uint8Array) => messages.push(parseVideoMessage(payload.buffer as ArrayBuffer)),
    });
    wss.emit("connection", ws);
    return {
      messages,
      get client() {
        return [...manager.wsStreamingClients.values()].find(client => client.ws === (ws as any))!;
      },
      send: (message: unknown) =>
        ws.emit("message", Buffer.from(typeof message === "string" ? message : JSON.stringify(message)), false),
    };
  };
  const broadcast = (keyframe = true) =>
    broadcastForPhase(manager.wsStreamingClients, StreamingPhase.RENDER, {
      type: WSMessageType.DATA,
      metadata: { keyframe, pts: "0" },
      data,
    });
  const configure = () =>
    broadcastForPhase(manager.wsStreamingClients, StreamingPhase.METADATA, {
      type: WSMessageType.CONFIGURATION,
      metadata: {},
      data,
    });
  return { connect, broadcast, configure };
}

test("only the running team receives video; other and late viewers must complete a fresh handshake to resume", t => {
  const manager = managerFixture(t);
  t.mock.method(manager, "requestVideoRefresh", () => {});
  const { connect, broadcast, configure } = streamingFixture(manager);
  const owner = connect();
  const other = connect();
  const anonymous = connect();
  owner.send({ type: WSMessageType.STREAM_TEAM, teamToken: teamA });
  other.send({ type: WSMessageType.STREAM_TEAM, teamToken: teamB });
  for (const viewer of [owner, other, anonymous]) viewer.send(WSMessageType.STREAM_METADATA_ACK);
  broadcast();
  assert.equal(anonymous.messages.at(-1)?.type, WSMessageType.DATA);

  manager.setActiveExploitTeam(teamA);
  assert.equal(owner.client.hidden, false);
  assert.equal(other.client.hidden, true);
  assert.equal(anonymous.client.hidden, true);
  assert.deepEqual(other.messages.at(-1)?.metadata, {
    hidden: true,
    teamAuthenticated: true,
    invalidTeamToken: false,
  });
  for (const viewer of [owner, other, anonymous]) viewer.messages.length = 0;
  other.send(WSMessageType.STREAM_METADATA_ACK);
  other.send(WSMessageType.STREAM_RESYNC);
  configure();
  broadcast();
  assert.equal(owner.messages.at(-1)?.type, WSMessageType.DATA);
  assert.deepEqual(other.messages, []);
  assert.deepEqual(anonymous.messages, []);
  assert.equal(other.client.state, StreamingPhase.INIT);

  const late = connect();
  assert.deepEqual(
    late.messages.map(message => message.type),
    [WSMessageType.STREAM_VISIBILITY],
  );
  late.send(WSMessageType.STREAM_METADATA_ACK);
  broadcast();
  assert.equal(late.messages.length, 1);
  late.send({ type: WSMessageType.STREAM_TEAM, teamToken: teamA });
  assert.equal(late.messages.at(-1)?.type, WSMessageType.STREAM_METADATA);
  assert.equal(late.client.hidden, false);
  late.send(WSMessageType.STREAM_METADATA_ACK);
  const count = late.messages.length;
  broadcast(false);
  assert.equal(late.messages.length, count);
  broadcast();
  assert.equal(late.messages.at(-1)?.type, WSMessageType.DATA);

  manager.setActiveExploitTeam(null);
  for (const viewer of [other, anonymous]) {
    assert.equal(viewer.client.hidden, false);
    assert.equal(viewer.client.state, StreamingPhase.INIT);
    assert.equal(viewer.messages.at(-1)?.type, WSMessageType.STREAM_METADATA);
    viewer.messages.length = 0;
  }
  broadcast();
  assert.deepEqual(other.messages, []);
  other.send(WSMessageType.STREAM_METADATA_ACK);
  assert.equal(other.messages[0].type, WSMessageType.CONFIGURATION);
  broadcast(false);
  assert.equal(other.messages.length, 1);
  broadcast();
  assert.equal(other.messages.at(-1)?.type, WSMessageType.DATA);
  assert.equal(JSON.stringify([...owner.messages, ...other.messages, ...late.messages]).includes(teamA), false);
});

test("invalid, cleared, or spoofed viewer tokens cannot reveal a private stream", t => {
  const manager = managerFixture(t);
  manager.setActiveExploitTeam(teamA);
  const viewer = streamingFixture(manager).connect();
  for (const token of [undefined, null, 1, [teamA], { token: teamA }, "unknown", teamB, ""]) {
    viewer.send({ type: WSMessageType.STREAM_TEAM, teamToken: token, hidden: false });
    viewer.send(WSMessageType.STREAM_METADATA_ACK);
    assert.equal(viewer.client.hidden, true);
    assert.equal(viewer.client.state, StreamingPhase.INIT);
  }
  viewer.send({ type: WSMessageType.STREAM_TEAM, teamToken: teamA });
  assert.equal(viewer.client.hidden, false);
  viewer.send({ type: WSMessageType.STREAM_TEAM, teamToken: "" });
  assert.equal(viewer.client.hidden, true);
  assert.deepEqual(viewer.messages.at(-1)?.metadata, {
    hidden: true,
    teamAuthenticated: false,
    invalidTeamToken: false,
  });
  assert.throws(() => manager.setActiveExploitTeam("unknown"), denied(401));
});

test("privacy discards queued input, releases held controls, and ignores hidden viewers' input and refresh requests", async t => {
  const manager = managerFixture(t);
  manager.getConfig().features.scrcpyControlEnabled = true;
  const calls: { method: string; input: any }[] = [];
  const record = (method: string) => async (input: any) => {
    calls.push({ method, input });
  };
  manager.setScrcpyClient({
    controller: {
      injectText: record("text"),
      injectTouch: record("touch"),
      injectKeyCode: record("key"),
    },
  } as any);
  const refresh = t.mock.method(manager, "requestVideoRefresh", () => {});
  const viewer = streamingFixture(manager).connect();
  viewer.send({ type: "control", event: "key", action: "down", keyCode: 66, metaState: 0, repeat: 0 });
  await tick();
  assert.equal(calls.length, 1);
  viewer.send({ type: "control", event: "text", text: "queued input" });
  manager.setActiveExploitTeam(teamA);
  viewer.send({ type: "control", event: "text", text: "hidden input" });
  viewer.send(WSMessageType.STREAM_METADATA_ACK);
  viewer.send(WSMessageType.STREAM_RESYNC);
  await tick();
  assert.deepEqual(
    calls.map(call => [call.method, call.input.action]),
    [
      ["key", 0],
      ["key", 1],
    ],
  );
  assert.equal(refresh.mock.callCount(), 0);
  viewer.send({ type: WSMessageType.STREAM_TEAM, teamToken: teamA });
  viewer.send({ type: "control", event: "text", text: "owner input" });
  await tick();
  assert.equal(calls.at(-1)?.input, "owner input");
});

test("privacy works for generated unlimited-team tokens and is inactive without team mode", t => {
  const manager = managerFixture(t, "-1");
  const token = manager.addTeam();
  manager.setActiveExploitTeam(token);
  assert.equal(manager.canViewStream(), false);
  assert.equal(manager.canViewStream(token), true);
  manager.getConfig().features.teamModeEnabled = false;
  manager.setActiveExploitTeam("ignored");
  assert.equal(manager.canViewStream(), true);
  assert.equal(streamingFixture(manager).connect().client.hidden, false);
});

test("a queued run passes its team identity to the exploit lifecycle", async t => {
  const manager = managerFixture(t);
  manager.registerInstalledApp(packageName, teamA);
  let job: any;
  t.mock.method(manager.queue, "enqueue", input => {
    job = input;
    return { ok: true, createdAt: 1 };
  });
  const launch = t.mock.method(APIController, "startExploitApp", async () => {});
  await APIController.enqueueStartExploitApp(
    { body: { packageName, teamToken: teamA } } as any,
    response() as any,
    () => {},
  );
  await job.run(1);
  assert.equal(launch.mock.calls[0].arguments[3], teamA);
});

test("privacy begins before launch and lasts through the duration and target restart", async t => {
  const manager = managerFixture(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  manager.getConfig().features.exploitAppDuration = 1;
  let finishLaunch!: () => void;
  let finishRecovery!: () => void;
  t.mock.method(
    manager,
    "runAppByPackageName",
    () =>
      new Promise<void>(resolve => {
        finishLaunch = resolve;
      }),
  );
  const recover = t.mock.method(
    manager,
    "runTargetApp",
    () =>
      new Promise<void>(resolve => {
        finishRecovery = resolve;
      }),
  );
  const run = APIController.startExploitApp("job", packageName, 0, teamA);
  assert.equal(manager.canViewStream(teamB), false);
  assert.equal(manager.canViewStream(teamA), true);
  finishLaunch();
  await tick();
  t.mock.timers.tick(999);
  assert.equal(recover.mock.callCount(), 0);
  t.mock.timers.tick(1);
  await tick();
  assert.equal(recover.mock.callCount(), 1);
  assert.equal(manager.canViewStream(teamB), false);
  finishRecovery();
  await run;
  assert.equal(manager.canViewStream(), true);
});

test("a failed launch restores the shared view only after successful recovery", async t => {
  const manager = managerFixture(t);
  t.mock.method(manager, "runAppByPackageName", async () => {
    throw new Error("launch failed");
  });
  const recover = t.mock.method(manager, "runTargetApp", async () => {
    assert.equal(manager.canViewStream(teamB), false);
  });
  await assert.rejects(APIController.startExploitApp("job", packageName, 0, teamA), /launch failed/);
  assert.equal(recover.mock.callCount(), 1);
  assert.equal(manager.canViewStream(), true);
  recover.mock.mockImplementation(async () => {
    throw new Error("recovery failed");
  });
  await assert.rejects(APIController.startExploitApp("job", packageName, 0, teamA), /recovery failed/);
  assert.equal(manager.canViewStream(teamB), false);
});
