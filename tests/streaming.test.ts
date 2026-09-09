import assert from "node:assert/strict";
import { test } from "node:test";
import { WebSocket } from "ws";
import type { ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import { getScrcpyVideoSettings, selectVideoEncoder } from "../src/server/config/scrcpy";
import { broadcastForPhase, MAX_VIDEO_BUFFER_BYTES, serializeStructuredMessage } from "../src/server/utils/ws";
import { LiveVideoDecoder, MAX_PENDING_VIDEO_FRAMES, parseVideoMessage } from "../src/client/utils/video-stream";
import { StreamingPhase, WSMessageType } from "../src/shared/types";

const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const data = new Uint8Array([1, 2, 3]);
const frame = (keyframe = false): ScrcpyMediaStreamPacket => ({ type: "data", keyframe, pts: 0n, data });

test("stream settings have lighter defaults, validated overrides, and full-resolution opt-out", () => {
  assert.deepEqual(getScrcpyVideoSettings({}), { maxSize: 1280, maxFps: 60, videoBitRate: 4_000_000 });
  assert.deepEqual(
    getScrcpyVideoSettings({
      DROIDGROUND_SCRCPY_MAX_SIZE: "0",
      DROIDGROUND_SCRCPY_MAX_FPS: "0",
      DROIDGROUND_SCRCPY_VIDEO_BIT_RATE: "10000000",
    }),
    { maxSize: 0, maxFps: 0, videoBitRate: 10_000_000 },
  );
  for (const value of ["", "no", "-1", "Infinity", "100000001", "1.5"]) {
    assert.deepEqual(
      getScrcpyVideoSettings({
        DROIDGROUND_SCRCPY_MAX_SIZE: value,
        DROIDGROUND_SCRCPY_MAX_FPS: value,
        DROIDGROUND_SCRCPY_VIDEO_BIT_RATE: value,
      }),
      getScrcpyVideoSettings({}),
    );
  }
});

test("encoder selection prefers H.264 hardware without choosing a different codec", () => {
  const software = { type: "video", codec: "h264", name: "software-avc", hardwareType: "software" } as const;
  const hardware = { type: "video", codec: "h264", name: "hardware-avc", hardwareType: "hardware" } as const;
  assert.equal(
    selectVideoEncoder([
      { type: "video", codec: "h265", name: "hardware-hevc", hardwareType: "hardware" },
      software,
      hardware,
    ]),
    hardware,
  );
  assert.equal(selectVideoEncoder([software]), software);
  assert.equal(selectVideoEncoder([{ type: "video", name: "legacy" }]).name, "legacy");
  assert.throws(() => selectVideoEncoder([{ type: "video", codec: "h265", name: "hevc" }]), /No H.264/);
});

function viewer(state: StreamingPhase = StreamingPhase.RENDER, bufferedAmount = 0) {
  const sent: Uint8Array[] = [];
  const ws = {
    readyState: WebSocket.OPEN as number,
    bufferedAmount,
    send: (payload: Uint8Array) => sent.push(payload),
  };
  return { client: { state, ws: ws as unknown as WebSocket }, ws, sent };
}

test("a broadcast packages the frame once and the browser reads its payload without copying", () => {
  const first = viewer();
  const second = viewer();
  broadcastForPhase(
    new Map([
      ["first", first.client],
      ["second", second.client],
    ]),
    StreamingPhase.RENDER,
    {
      type: WSMessageType.DATA,
      metadata: { keyframe: true, pts: "0" },
      data,
    },
  );
  assert.equal(first.sent.length, 1);
  assert.equal(first.sent[0], second.sent[0]);
  const parsed = parseVideoMessage(first.sent[0].buffer as ArrayBuffer);
  assert.equal(parsed.type, WSMessageType.DATA);
  assert.deepEqual(parsed.metadata, { keyframe: true, pts: "0" });
  assert.equal(parsed.data.buffer, first.sent[0].buffer);
  assert.deepEqual(parsed.data, data);
});

test("slow viewers skip a dependent frame sequence and resume at a fresh keyframe", () => {
  const slow = viewer(StreamingPhase.RENDER, MAX_VIDEO_BUFFER_BYTES + 1);
  const fast = viewer();
  const viewers = new Map([
    ["slow", slow.client],
    ["fast", fast.client],
  ]);
  const broadcast = (keyframe: boolean) =>
    broadcastForPhase(viewers, StreamingPhase.RENDER, {
      type: WSMessageType.DATA,
      metadata: { keyframe, pts: "0" },
      data,
    });
  broadcast(false);
  assert.equal(slow.client.state, StreamingPhase.KEYFRAME);
  assert.equal(slow.sent.length, 0);
  assert.equal(fast.sent.length, 1);
  slow.ws.bufferedAmount = 0;
  broadcast(false);
  assert.equal(slow.sent.length, 0);
  broadcast(true);
  assert.equal(slow.sent.length, 1);
  assert.equal(slow.client.state, StreamingPhase.RENDER);
  broadcast(false);
  assert.equal(slow.sent.length, 2);
  fast.ws.readyState = WebSocket.CLOSED;
  broadcast(false);
  assert.equal(fast.sent.length, 4);
});

test("rotation sends a configuration message to every initialized viewer before more frames", () => {
  const waiting = viewer(StreamingPhase.METADATA);
  const playing = viewer();
  const initial = viewer(StreamingPhase.INIT);
  const viewers = new Map([
    ["waiting", waiting.client],
    ["playing", playing.client],
    ["initial", initial.client],
  ]);
  broadcastForPhase(viewers, StreamingPhase.METADATA, { type: WSMessageType.CONFIGURATION, metadata: {}, data });
  assert.equal(initial.sent.length, 0);
  for (const client of [waiting, playing]) {
    assert.equal(client.client.state, StreamingPhase.METADATA);
    assert.equal(parseVideoMessage(client.sent[0].buffer as ArrayBuffer).type, WSMessageType.CONFIGURATION);
  }
  broadcastForPhase(viewers, StreamingPhase.RENDER, {
    type: WSMessageType.DATA,
    metadata: { keyframe: true, pts: "0" },
    data,
  });
  assert.equal(playing.sent.length, 1);
});

test("video parsing rejects truncated headers and metadata", () => {
  assert.throws(() => parseVideoMessage(new ArrayBuffer(3)), /Truncated/);
  const invalid = new ArrayBuffer(5);
  new DataView(invalid).setUint32(0, 100);
  assert.throws(() => parseVideoMessage(invalid), /Truncated/);
  const valid = serializeStructuredMessage(WSMessageType.CONFIGURATION, {}, data);
  assert.equal(parseVideoMessage(valid.buffer).type, WSMessageType.CONFIGURATION);
});

function decoderFactory() {
  const decoders: ReturnType<typeof create>[] = [];
  function create() {
    const packets: ScrcpyMediaStreamPacket[] = [];
    const decoder = {
      framesRendered: 0,
      framesSkipped: 0,
      disposed: false,
      packets,
      writable: new WritableStream<ScrcpyMediaStreamPacket>({
        write: packet => {
          packets.push(packet);
        },
      }),
      dispose: () => {
        decoder.disposed = true;
      },
    };
    decoders.push(decoder);
    return decoder;
  }
  return { create, decoders };
}

test("browser decoding starts with configuration and a keyframe, then keeps dependent frames ordered", async () => {
  const { create, decoders } = decoderFactory();
  const live = new LiveVideoDecoder(create, assert.fail);
  live.configure(data);
  live.push(frame());
  live.push(frame(true));
  live.push(frame());
  await tick();
  assert.deepEqual(
    decoders[0].packets.map(p => p.type),
    ["configuration", "data", "data"],
  );
  live.dispose();
  await tick();
  assert.equal(decoders[0].disposed, true);
  live.push(frame(true));
  assert.equal(decoders.length, 1);
});

test("a stalled browser decoder has a bounded queue and resumes on the next live keyframe", async () => {
  const { create, decoders } = decoderFactory();
  const live = new LiveVideoDecoder(create, assert.fail);
  live.configure(data);
  live.push(frame(true));
  for (let i = 1; i < MAX_PENDING_VIDEO_FRAMES; i++) live.push(frame());
  await tick();
  assert.equal(decoders[0].packets.length, MAX_PENDING_VIDEO_FRAMES + 1);
  live.push(frame());
  await tick();
  assert.equal(decoders[0].disposed, true);
  live.push(frame());
  assert.equal(decoders.length, 1);
  live.push(frame(true));
  await tick();
  assert.deepEqual(
    decoders[1].packets.map(p => p.type),
    ["configuration", "data"],
  );
  live.dispose();
});

test("rendered and skipped frame counts allow healthy decoders to keep streaming", async () => {
  const { create, decoders } = decoderFactory();
  const live = new LiveVideoDecoder(create, assert.fail);
  live.configure(data);
  for (let i = 0; i < 60; i++) {
    live.push(frame(i === 0));
    await tick();
    if (i % 2) decoders[0].framesSkipped++;
    else decoders[0].framesRendered++;
  }
  assert.equal(decoders.length, 1);
  assert.equal(decoders[0].packets.length, 61);
  live.dispose();
});

test("hidden tabs stop decoding and resume from a fresh keyframe", async () => {
  const { create, decoders } = decoderFactory();
  const live = new LiveVideoDecoder(create, assert.fail);
  live.configure(data);
  live.push(frame(true));
  await tick();
  live.push(frame(), false);
  await tick();
  assert.equal(decoders[0].disposed, true);
  live.push(frame(true), false);
  live.push(frame());
  assert.equal(decoders.length, 1);
  live.push(frame(true));
  await tick();
  assert.equal(decoders.length, 2);
  live.dispose();
});

test("decoder initialization failure allows a fallback to consume the cached configuration", async () => {
  const { create, decoders } = decoderFactory();
  let fallback = false;
  const live = new LiveVideoDecoder(
    () => {
      if (!fallback) throw new Error("WebCodecs unavailable");
      return create();
    },
    () => {
      fallback = true;
    },
  );
  live.configure(data);
  assert.equal(fallback, true);
  live.push(frame(true));
  await tick();
  assert.deepEqual(
    decoders[0].packets.map(p => p.type),
    ["configuration", "data"],
  );
  live.dispose();
});

test("reconfiguration waits for an in-progress write before disposing its decoder", async () => {
  const { create, decoders } = decoderFactory();
  const first = create();
  let finish!: () => void;
  first.writable = new WritableStream({
    write: () =>
      new Promise<void>(resolve => {
        finish = resolve;
      }),
  });
  let calls = 0;
  const live = new LiveVideoDecoder(() => (calls++ === 0 ? first : create()), assert.fail);
  live.configure(data);
  await tick();
  live.configure(new Uint8Array([4, 5, 6]));
  assert.equal(first.disposed, false);
  finish();
  await tick();
  assert.equal(first.disposed, true);
  live.push(frame(true));
  await tick();
  assert.equal(decoders[1].packets.length, 2);
  live.dispose();
});
