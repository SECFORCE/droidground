import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { rmSync } from "node:fs";
import { test } from "node:test";
import { WebSocket } from "ws";
import { VideoRefreshScheduler, VIDEO_REFRESH_DELAY_MS } from "../src/server/utils/video-refresh";
import { ManagerSingleton } from "../src/server/manager";
import { setupScrcpyWss } from "../src/server/ws/scrcpy";
import { broadcastForPhase } from "../src/server/utils/ws";
import { parseVideoMessage } from "../src/client/utils/video-stream";
import { StreamingPhase, WSMessageType } from "../src/shared/types";
import Logger from "../src/shared/logger";

const tick = () => new Promise<void>(resolve => setImmediate(resolve));

test("refresh requests are coalesced and cancelled when a normal keyframe arrives", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let waiting = true;
  let refreshes = 0;
  const scheduler = new VideoRefreshScheduler(
    () => waiting,
    async () => {
      refreshes++;
    },
    assert.fail,
  );
  t.after(() => scheduler.dispose());
  for (let i = 0; i < 100; i++) scheduler.request();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS - 1);
  assert.equal(refreshes, 0);
  t.mock.timers.tick(1);
  await tick();
  assert.equal(refreshes, 1);
  scheduler.request();
  waiting = false;
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  await tick();
  assert.equal(refreshes, 1);
});

test("an in-progress refresh cannot be duplicated, and failures are handled", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let finish!: () => void;
  let refreshes = 0;
  const errors: unknown[] = [];
  const scheduler = new VideoRefreshScheduler(
    () => true,
    async () => {
      refreshes++;
      if (refreshes === 1)
        await new Promise<void>(resolve => {
          finish = resolve;
        });
      else throw new Error("encoder disconnected");
    },
    error => errors.push(error),
  );
  t.after(() => scheduler.dispose());
  scheduler.request();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  scheduler.request();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  assert.equal(refreshes, 1);
  finish();
  await tick();
  scheduler.request();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  await tick();
  assert.equal(refreshes, 2);
  assert.equal(errors.length, 1);
  scheduler.request();
  scheduler.dispose();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  assert.equal(refreshes, 2);
});

test("a late ReDroid viewer recovers without waiting for an IDR interval or losing the refresh IDR to an ACK", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.mock.method(Logger, "info", () => {});
  const clients = new Map();
  const data = new Uint8Array([0, 0, 0, 1, 0x65]);
  const broadcast = (keyframe: boolean) =>
    broadcastForPhase(clients, StreamingPhase.RENDER, {
      type: WSMessageType.DATA,
      metadata: { keyframe, pts: "0" },
      data,
    });
  let refreshes = 0;
  const refresh = new VideoRefreshScheduler(
    () => [...clients.values()].some(client => client.state === StreamingPhase.KEYFRAME),
    async () => {
      refreshes++;
      // Scrcpy can emit the config and first IDR together, before any browser ACK.
      broadcastForPhase(clients, StreamingPhase.METADATA, { type: WSMessageType.CONFIGURATION, metadata: {}, data });
      broadcast(true);
    },
    assert.fail,
  );
  t.after(() => refresh.dispose());
  t.mock.method(
    ManagerSingleton,
    "getInstance",
    () =>
      ({
        wsStreamingClients: clients,
        sharedVideoMetadata: { videoEncoder: "OMX.google.h264.encoder", hardwareType: "hybrid" },
        sharedConfiguration: { data },
        getConfig: () => ({ features: { scrcpyControlEnabled: false } }),
        getScrcpyController: () => undefined,
        requestVideoRefresh: () => refresh.request(),
      }) as any,
  );
  const messages: ReturnType<typeof parseVideoMessage>[] = [];
  const ws = Object.assign(new EventEmitter(), {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    send: (payload: Uint8Array) => messages.push(parseVideoMessage(payload.buffer as ArrayBuffer)),
  });
  const wss = new EventEmitter();
  setupScrcpyWss(wss as any);
  wss.emit("connection", ws);
  const send = (message: WSMessageType) => ws.emit("message", Buffer.from(message), false);
  send(WSMessageType.STREAM_METADATA_ACK);
  send(WSMessageType.CONFIGURATION_ACK);
  // The initial IDR was produced before this viewer joined. Periodic I-frames
  // without the sync-frame flag must not be mislabeled as independently decodable.
  for (let i = 0; i < 20; i++) broadcast(false);
  assert.equal(messages.filter(message => message.type === WSMessageType.DATA).length, 0);
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  await tick();
  assert.equal(refreshes, 1);
  assert.equal(messages.at(-1)?.type, WSMessageType.DATA);
  assert.equal([...clients.values()][0].state, StreamingPhase.RENDER);
  send(WSMessageType.CONFIGURATION_ACK);
  assert.equal([...clients.values()][0].state, StreamingPhase.RENDER);
  broadcast(false);
  assert.equal(messages.filter(message => message.type === WSMessageType.DATA).length, 2);
  // Browser recovery uses the same mechanism, including while input is disabled.
  send(WSMessageType.STREAM_RESYNC);
  assert.equal([...clients.values()][0].state, StreamingPhase.KEYFRAME);
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  await tick();
  assert.equal(refreshes, 2);
  assert.equal([...clients.values()][0].state, StreamingPhase.RENDER);
  ws.emit("close");
});

test("internal video refresh works while the manager denies browser device input", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.mock.method(Logger, "info", () => {});
  const originalEnabled = process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED;
  const originalIP = process.env.DROIDGROUND_IP_STATIC;
  process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED = "false";
  process.env.DROIDGROUND_IP_STATIC = "127.0.0.1";
  t.after(() => {
    if (originalEnabled === undefined) delete process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED;
    else process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED = originalEnabled;
    if (originalIP === undefined) delete process.env.DROIDGROUND_IP_STATIC;
    else process.env.DROIDGROUND_IP_STATIC = originalIP;
  });
  const manager = Reflect.construct(ManagerSingleton, []) as ManagerSingleton;
  t.after(() => rmSync(manager.getTmpDir(), { recursive: true, force: true }));
  let refreshes = 0;
  manager.setScrcpyClient({
    controller: {
      resetVideo: async () => {
        refreshes++;
      },
    },
  } as any);
  manager.wsStreamingClients.set("viewer", {
    state: StreamingPhase.KEYFRAME,
    ws: { readyState: WebSocket.OPEN } as WebSocket,
  });
  assert.equal(manager.getScrcpyController(), undefined);
  manager.requestVideoRefresh();
  t.mock.timers.tick(VIDEO_REFRESH_DELAY_MS);
  await tick();
  assert.equal(refreshes, 1);
  assert.equal(manager.getScrcpyController(), undefined);
});
