import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { rmSync } from "node:fs";
import { test } from "node:test";
import { AndroidKeyCode } from "@yume-chan/scrcpy";
import { bindScrcpyControls, screenPosition } from "../src/client/utils/scrcpy-control";
import { parseScrcpyControlMessage, ScrcpyControlSession } from "../src/server/utils/scrcpy-control";
import { ManagerSingleton } from "../src/server/manager";
import { setupScrcpyWss } from "../src/server/ws/scrcpy";
import Logger from "../src/shared/logger";
import { StreamingPhase, WSMessageType } from "../src/shared/types";

const touch = {
  type: "control",
  event: "touch",
  action: "down",
  pointerId: 1,
  x: 25,
  y: 50,
  width: 100,
  height: 200,
  pressure: 1,
};
const key = { type: "control", event: "key", action: "down", keyCode: AndroidKeyCode.Enter, metaState: 0, repeat: 0 };
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

function recorder() {
  const calls: { method: string; input: any }[] = [];
  const record = (method: string) => async (input: any) => {
    calls.push({ method, input });
  };
  return {
    calls,
    writer: {
      injectTouch: record("touch"),
      injectKeyCode: record("key"),
      injectScroll: record("scroll"),
      injectText: record("text"),
    },
  };
}

test("control messages reject malformed, oversized, and out-of-range input", () => {
  assert.deepEqual(parseScrcpyControlMessage(JSON.stringify(touch)), touch);
  for (const invalid of [
    null,
    [],
    { ...touch, width: 0 },
    { ...touch, height: 65536 },
    { ...touch, x: 100 },
    { ...touch, y: -1 },
    { ...touch, x: 0.5 },
    { ...touch, pressure: 2 },
    { ...touch, pointerId: -1 },
    { ...touch, action: "unknown" },
    { ...key, keyCode: 999999 },
    { ...key, repeat: -1 },
    { type: "control", event: "text", text: "a".repeat(301) },
    { ...touch, event: "scroll", scrollX: 0, scrollY: 2 },
  ])
    assert.equal(parseScrcpyControlMessage(JSON.stringify(invalid)), undefined);
  assert.equal(parseScrcpyControlMessage("{"), undefined);
  assert.equal(parseScrcpyControlMessage(" ".repeat(4097)), undefined);
});

test("gestures are ordered, orphan events ignored, and held inputs released on disconnect", async () => {
  const { writer, calls } = recorder();
  const session = new ScrcpyControlSession(() => writer, assert.fail);
  session.accept(JSON.stringify({ ...touch, action: "move" }));
  session.accept(JSON.stringify(touch));
  session.accept(JSON.stringify({ ...touch, action: "move", x: 40 }));
  session.accept(JSON.stringify(key));
  await session.close();
  assert.deepEqual(
    calls.map(c => [c.method, c.input.action]),
    [
      ["touch", 0],
      ["touch", 2],
      ["key", 0],
      ["touch", 1],
      ["key", 1],
    ],
  );
  assert.equal(calls[3].input.pointerX, 40);
  assert.equal(calls[3].input.pressure, 0);
  const length = calls.length;
  session.accept(JSON.stringify(touch));
  await session.close();
  assert.equal(calls.length, length);
});

test("viewers receive separate pointer IDs and cleanup only releases their own touches", async () => {
  const { writer, calls } = recorder();
  const first = new ScrcpyControlSession(() => writer, assert.fail);
  const second = new ScrcpyControlSession(() => writer, assert.fail);
  first.accept(JSON.stringify(touch));
  second.accept(JSON.stringify(touch));
  await tick();
  assert.notEqual(calls[0].input.pointerId, calls[1].input.pointerId);
  await first.close();
  assert.equal(calls[2].input.pointerId, calls[0].input.pointerId);
  await second.close();
  assert.equal(calls[3].input.pointerId, calls[1].input.pointerId);
});

test("a missing controller drops input, and queued input never reaches a replacement controller", async () => {
  const first = recorder();
  const second = recorder();
  let writer: typeof first.writer | undefined;
  const session = new ScrcpyControlSession(() => writer, assert.fail);
  session.accept(JSON.stringify(touch));
  writer = first.writer;
  session.accept(JSON.stringify(touch));
  writer = second.writer;
  await tick();
  assert.equal(first.calls.length, 0);
  assert.equal(second.calls.length, 0);
  session.accept(JSON.stringify({ type: "control", event: "text", text: "hello" }));
  await session.close();
  assert.deepEqual(second.calls, [{ method: "text", input: "hello" }]);
});

test("pending input is bounded when the device writer stalls", async () => {
  const { writer } = recorder();
  let unblock!: () => void;
  const stalled = new Promise<void>(resolve => {
    unblock = resolve;
  });
  writer.injectText = () => stalled;
  const session = new ScrcpyControlSession(() => writer, assert.fail);
  const message = JSON.stringify({ type: "control", event: "text", text: "a" });
  for (let i = 0; i < 256; i++) assert.equal(session.accept(message), true);
  assert.equal(session.accept(message), false);
  unblock();
  await session.close();
});

test("writer errors are reported and do not prevent cleanup", async () => {
  const { writer, calls } = recorder();
  const errors: unknown[] = [];
  writer.injectText = async () => {
    throw new Error("device disconnected");
  };
  const session = new ScrcpyControlSession(
    () => writer,
    error => errors.push(error),
  );
  session.accept(JSON.stringify(touch));
  session.accept(JSON.stringify({ type: "control", event: "text", text: "a" }));
  await session.close();
  assert.equal(errors.length, 1);
  assert.deepEqual(
    calls.map(c => c.input.action),
    [0, 1],
  );
});

test("ENV defaults to disabled and only exact true exposes the controller", t => {
  t.mock.method(Logger, "info", () => {});
  const original = process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED;
  const originalIP = process.env.DROIDGROUND_IP_STATIC;
  process.env.DROIDGROUND_IP_STATIC = "127.0.0.1";
  try {
    for (const value of [undefined, "false", "TRUE", "1", "true"]) {
      if (value === undefined) delete process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED;
      else process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED = value;
      const manager = Reflect.construct(ManagerSingleton, []) as ManagerSingleton;
      try {
        const { writer } = recorder();
        manager.setScrcpyClient({ controller: writer } as any);
        assert.equal(manager.getConfig().features.scrcpyControlEnabled, value === "true");
        assert.equal(manager.getScrcpyController(), value === "true" ? writer : undefined);
      } finally {
        rmSync(manager.getTmpDir(), { recursive: true, force: true });
      }
    }
  } finally {
    if (originalIP === undefined) delete process.env.DROIDGROUND_IP_STATIC;
    else process.env.DROIDGROUND_IP_STATIC = originalIP;
    if (original === undefined) delete process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED;
    else process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED = original;
  }
});

test("streaming ACKs work with control disabled; enabled control forwards text and ignores binary input", async t => {
  t.mock.method(Logger, "info", () => {});
  const { writer, calls } = recorder();
  const features = { scrcpyControlEnabled: false };
  const clients = new Map();
  t.mock.method(
    ManagerSingleton,
    "getInstance",
    () =>
      ({
        wsStreamingClients: clients,
        sharedVideoMetadata: { hardwareType: "software" },
        getConfig: () => ({ features }),
        getScrcpyController: () => writer,
      }) as any,
  );
  const wss = new EventEmitter();
  const ws = Object.assign(new EventEmitter(), { send: () => {} });
  setupScrcpyWss(wss as any);
  wss.emit("connection", ws);
  const send = (message: string, binary = false) => ws.emit("message", Buffer.from(message), binary);
  send(WSMessageType.STREAM_METADATA_ACK);
  assert.equal([...clients.values()][0].state, StreamingPhase.METADATA);
  send(WSMessageType.CONFIGURATION_ACK);
  assert.equal([...clients.values()][0].state, StreamingPhase.RENDER);
  const text = JSON.stringify({ type: "control", event: "text", text: "hello" });
  send(text);
  await tick();
  assert.equal(calls.length, 0);
  features.scrcpyControlEnabled = true;
  send(text, true);
  send(text);
  await tick();
  assert.deepEqual(calls, [{ method: "text", input: "hello" }]);
  ws.emit("close");
  await tick();
  assert.equal(clients.size, 0);
});

function fakeScreen() {
  const canvas = {
    width: 1080,
    height: 1920,
    getBoundingClientRect: () => ({ left: 20, top: 30, width: 270, height: 480 }),
  };
  const captured = new Set<number>();
  const element = Object.assign(new EventTarget(), {
    querySelector: () => canvas,
    focus: () => {},
    setPointerCapture: (id: number) => captured.add(id),
    hasPointerCapture: (id: number) => captured.has(id),
    releasePointerCapture: (id: number) => captured.delete(id),
  });
  const fire = (type: string, fields = {}) => {
    const event = Object.assign(new Event(type, { cancelable: true }), fields);
    element.dispatchEvent(event);
    return event;
  };
  return { canvas, element, captured, fire };
}

test("coordinates use canvas bounds and current resolution, including after rotation", () => {
  const { canvas } = fakeScreen();
  assert.deepEqual(screenPosition(canvas as any, 155, 270, false), { x: 540, y: 960, width: 1080, height: 1920 });
  assert.equal(screenPosition(canvas as any, 0, 0, false), undefined);
  assert.deepEqual(screenPosition(canvas as any, 500, 1000, true), { x: 1079, y: 1919, width: 1080, height: 1920 });
  canvas.width = 1920;
  canvas.height = 1080;
  assert.deepEqual(screenPosition(canvas as any, 155, 270, false), { x: 960, y: 540, width: 1920, height: 1080 });
});

test("screen events support multitouch, captured drags, scroll, focused keyboard input, and cleanup", t => {
  const oldWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const oldDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "window", { configurable: true, value: new EventTarget() });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: Object.assign(new EventTarget(), { hidden: false }),
  });
  t.after(() => {
    if (oldWindow) Object.defineProperty(globalThis, "window", oldWindow);
    else delete (globalThis as any).window;
    if (oldDocument) Object.defineProperty(globalThis, "document", oldDocument);
    else delete (globalThis as any).document;
  });
  const { element, captured, fire } = fakeScreen();
  const messages: any[] = [];
  const dispose = bindScrcpyControls(element as any, message => messages.push(message));
  const pointer = {
    pointerId: 1,
    button: 0,
    buttons: 1,
    pointerType: "touch",
    pressure: 0.7,
    clientX: 155,
    clientY: 270,
  };
  assert.equal(fire("pointerdown", pointer).defaultPrevented, true);
  fire("pointerdown", { ...pointer, pointerId: 2 });
  assert.equal(captured.size, 2);
  fire("pointermove", { ...pointer, clientX: 999 });
  assert.equal(messages.at(-1).x, 1079);
  fire("pointercancel", pointer);
  assert.equal(messages.at(-1).action, "up");
  assert.equal(messages.at(-1).x, 1079);
  assert.equal(captured.has(1), false);
  fire("wheel", { clientX: 155, clientY: 270, deltaMode: 0, deltaX: 0, deltaY: 50 });
  assert.equal(messages.at(-1).scrollY, -0.5);
  const beforeLongPress = messages.length;
  fire("contextmenu", { ...pointer, button: 2 });
  assert.equal(messages.length, beforeLongPress);
  fire("contextmenu", { ...pointer, pointerType: "mouse", button: 2 });
  assert.equal(messages.at(-1).keyCode, AndroidKeyCode.AndroidBack);
  assert.equal(messages.at(-1).action, "up");
  fire("pointerdown", { ...pointer, pointerId: 3, pointerType: "mouse" });
  fire("lostpointercapture", { pointerId: 3 });
  assert.equal(messages.at(-1).action, "up");
  assert.equal(messages.at(-1).x, 540);
  fire("keydown", { code: "KeyA", key: "A", shiftKey: true });
  assert.deepEqual(messages.at(-1), { type: "control", event: "text", text: "A" });
  fire("keydown", { code: "ArrowDown", key: "ArrowDown", ctrlKey: true });
  assert.equal(messages.at(-1).metaState, 4096);
  fire("keydown", { code: "ArrowDown", key: "ArrowDown", repeat: true });
  assert.equal(messages.at(-1).repeat, 1);
  fire("keyup", { code: "ArrowDown" });
  assert.equal(messages.at(-1).action, "up");
  assert.equal(fire("keydown", { code: "Tab", key: "Tab" }).defaultPrevented, false);
  fire("keydown", { code: "Escape", key: "Escape" });
  assert.equal(messages.at(-1).keyCode, AndroidKeyCode.AndroidBack);
  fire("blur");
  assert.deepEqual(messages.at(-1), { type: "control", event: "release" });
  assert.equal(captured.size, 0);
  dispose();
  const count = messages.length;
  fire("pointerdown", pointer);
  fire("keydown", { code: "KeyA", key: "a" });
  assert.equal(messages.length, count);
});
