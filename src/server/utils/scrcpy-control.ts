import {
  AndroidKeyCode,
  AndroidKeyEventAction,
  AndroidKeyEventMeta,
  AndroidMotionEventAction,
} from "@yume-chan/scrcpy";
import type { ScrcpyControlMessageWriter } from "@yume-chan/scrcpy";
import type { ScrcpyControlMessage, ScrcpyTouchInput } from "@shared/scrcpy-control";

type ControlWriter = Pick<ScrcpyControlMessageWriter, "injectTouch" | "injectScroll" | "injectKeyCode" | "injectText">;
const keyCodes = new Set<number>(Object.values(AndroidKeyCode));
const integer = (value: unknown, min: number, max: number): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
const fraction = (value: unknown, min: number, max: number): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;

export function parseScrcpyControlMessage(raw: string): ScrcpyControlMessage | undefined {
  if (Buffer.byteLength(raw) > 4096) return;
  let message;
  try {
    message = JSON.parse(raw);
  } catch {
    return;
  }
  if (!message || typeof message !== "object" || message.type !== "control") return;
  switch (message.event) {
    case "release":
      return message;
    case "text":
      if (typeof message.text === "string" && message.text.length > 0 && message.text.length <= 300) return message;
      return;
    case "key":
      if (
        (message.action === "down" || message.action === "up") &&
        keyCodes.has(message.keyCode) &&
        integer(message.metaState, 0, 0x7fffff) &&
        integer(message.repeat, 0, 65535)
      )
        return message;
      return;
    case "touch":
    case "scroll":
      if (
        !integer(message.width, 1, 65535) ||
        !integer(message.height, 1, 65535) ||
        !integer(message.x, 0, message.width - 1) ||
        !integer(message.y, 0, message.height - 1)
      )
        return;
      if (message.event === "scroll") {
        if (fraction(message.scrollX, -1, 1) && fraction(message.scrollY, -1, 1)) return message;
      } else if (
        ["down", "move", "up"].includes(message.action) &&
        integer(message.pointerId, 0, Number.MAX_SAFE_INTEGER) &&
        fraction(message.pressure, 0, 1)
      )
        return message;
  }
}

// Allocate device pointer IDs across all viewers, independently of browser pointer IDs.
let nextPointerId = 0n;

export class ScrcpyControlSession {
  private queue = Promise.resolve();
  private pending = 0;
  private closed = false;
  private writer?: ControlWriter;
  private pointers = new Map<number, { id: bigint; input: ScrcpyTouchInput }>();
  private keys = new Set<number>();

  constructor(
    private getWriter: () => ControlWriter | undefined,
    private onError: (error: unknown) => void,
  ) {}

  accept(raw: string): boolean {
    const writer = this.getWriter();
    if (this.closed || !writer) return true;
    const message = parseScrcpyControlMessage(raw);
    if (!message) return true;
    if (this.pending >= 256) return false;
    this.enqueue(async () => {
      // Don't deliver queued inputs to a replacement device connection.
      if (writer !== this.getWriter()) return;
      if (this.writer !== writer) {
        this.pointers.clear();
        this.keys.clear();
        this.writer = writer;
      }
      await this.dispatch(writer, message);
    });
    return true;
  }

  private enqueue(run: () => Promise<void>) {
    this.pending++;
    this.queue = this.queue
      .then(run)
      .catch(this.onError)
      .finally(() => {
        this.pending--;
      });
  }

  private async dispatch(writer: ControlWriter, message: ScrcpyControlMessage) {
    switch (message.event) {
      case "release":
        await this.release(writer);
        break;
      case "text":
        await writer.injectText(message.text);
        break;
      case "key":
        if (message.action === "down") {
          if (this.keys.size >= 32 && !this.keys.has(message.keyCode)) return;
          this.keys.add(message.keyCode);
        } else if (!this.keys.delete(message.keyCode)) return;
        await writer.injectKeyCode({
          action: message.action === "down" ? AndroidKeyEventAction.Down : AndroidKeyEventAction.Up,
          keyCode: message.keyCode as AndroidKeyCode,
          metaState: message.metaState as AndroidKeyEventMeta,
          repeat: message.repeat,
        });
        break;
      case "scroll":
        await writer.injectScroll({
          pointerX: message.x,
          pointerY: message.y,
          videoWidth: message.width,
          videoHeight: message.height,
          scrollX: message.scrollX,
          scrollY: message.scrollY,
          buttons: 0,
        });
        break;
      case "touch": {
        let pointer = this.pointers.get(message.pointerId);
        if (message.action === "down") {
          if (pointer || this.pointers.size >= 10) return;
          pointer = { id: nextPointerId++, input: message };
          this.pointers.set(message.pointerId, pointer);
        }
        if (!pointer) return;
        pointer.input = message;
        await this.touch(writer, pointer.id, message);
        if (message.action === "up") this.pointers.delete(message.pointerId);
        break;
      }
    }
  }

  private touch(writer: ControlWriter, id: bigint, input: ScrcpyTouchInput) {
    return writer.injectTouch({
      action:
        input.action === "down"
          ? AndroidMotionEventAction.Down
          : input.action === "up"
            ? AndroidMotionEventAction.Up
            : AndroidMotionEventAction.Move,
      pointerId: id,
      pointerX: input.x,
      pointerY: input.y,
      videoWidth: input.width,
      videoHeight: input.height,
      pressure: input.action === "up" ? 0 : input.pressure,
      actionButton: 0,
      buttons: 0,
    });
  }

  private async release(writer: ControlWriter) {
    const pointers = [...this.pointers.values()];
    const keys = [...this.keys];
    this.pointers.clear();
    this.keys.clear();
    for (const { id, input } of pointers) {
      await this.touch(writer, id, { ...input, action: "up", pressure: 0 }).catch(this.onError);
    }
    for (const keyCode of keys) {
      await writer
        .injectKeyCode({
          action: AndroidKeyEventAction.Up,
          keyCode: keyCode as AndroidKeyCode,
          metaState: 0,
          repeat: 0,
        })
        .catch(this.onError);
    }
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      this.enqueue(async () => {
        if (this.writer && this.writer === this.getWriter()) await this.release(this.writer);
        this.pointers.clear();
        this.keys.clear();
      });
    }
    return this.queue;
  }
}
