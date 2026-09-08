import { AndroidKeyCode, AndroidKeyEventMeta } from "@yume-chan/scrcpy";
import type { ScrcpyControlMessage, ScrcpyPosition, ScrcpyTouchInput } from "@shared/scrcpy-control";

export function screenPosition(
  canvas: HTMLCanvasElement,
  clientX: number,
  clientY: number,
  clamp: boolean,
): ScrcpyPosition | undefined {
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height || !canvas.width || !canvas.height) return;
  const x = (clientX - rect.left) / rect.width;
  const y = (clientY - rect.top) / rect.height;
  if (!clamp && (x < 0 || x > 1 || y < 0 || y > 1)) return;
  return {
    x: Math.max(0, Math.min(canvas.width - 1, Math.floor(x * canvas.width))),
    y: Math.max(0, Math.min(canvas.height - 1, Math.floor(y * canvas.height))),
    width: canvas.width,
    height: canvas.height,
  };
}

// Bind to the common screen container so both decoders use identical controls.
export function bindScrcpyControls(element: HTMLElement, send: (message: ScrcpyControlMessage) => void) {
  const pointers = new Map<number, ScrcpyTouchInput>();
  const keys = new Map<string, { keyCode: number; repeat: number }>();
  const position = (event: MouseEvent, clamp = false) => {
    const canvas = element.querySelector("canvas");
    return canvas ? screenPosition(canvas, event.clientX, event.clientY, clamp) : undefined;
  };

  const release = () => {
    send({ type: "control", event: "release" });
    const ids = [...pointers.keys()];
    pointers.clear();
    keys.clear();
    for (const id of ids) {
      if (element.hasPointerCapture(id)) element.releasePointerCapture(id);
    }
  };

  const pointerUp = (event: PointerEvent) => {
    const previous = pointers.get(event.pointerId);
    if (!previous) return;
    event.preventDefault();
    pointers.delete(event.pointerId);
    // Cancellation/capture-loss events may not carry the last pointer coordinates.
    send({
      ...previous,
      ...(event.type === "pointerup" ? position(event, true) : undefined),
      action: "up",
      pressure: 0,
    });
    if (element.hasPointerCapture(event.pointerId)) element.releasePointerCapture(event.pointerId);
  };

  const pointerDown = (event: PointerEvent) => {
    if (event.button !== 0 || pointers.has(event.pointerId)) return;
    const point = position(event);
    if (!point) return;
    event.preventDefault();
    element.focus({ preventScroll: true });
    element.setPointerCapture(event.pointerId);
    const input: ScrcpyTouchInput = {
      type: "control",
      event: "touch",
      action: "down",
      pointerId: event.pointerId,
      pressure: event.pointerType === "mouse" ? 1 : event.pressure || 0.5,
      ...point,
    };
    pointers.set(event.pointerId, input);
    send(input);
  };

  const pointerMove = (event: PointerEvent) => {
    const previous = pointers.get(event.pointerId);
    if (!previous) return;
    if (event.pointerType === "mouse" && !(event.buttons & 1)) {
      pointerUp(event);
      return;
    }
    const point = position(event, true);
    if (!point) return;
    event.preventDefault();
    const input: ScrcpyTouchInput = {
      ...previous,
      ...point,
      action: "move",
      pressure: event.pointerType === "mouse" ? 1 : event.pressure || 0.5,
    };
    pointers.set(event.pointerId, input);
    send(input);
  };

  const wheel = (event: WheelEvent) => {
    const point = position(event);
    if (!point) return;
    event.preventDefault();
    // Pixel wheels and line/page wheels use different units; scrcpy expects [-1, 1].
    const unit = event.deltaMode === 0 ? 100 : event.deltaMode === 1 ? 3 : 1;
    send({
      type: "control",
      event: "scroll",
      ...point,
      scrollX: Math.max(-1, Math.min(1, -event.deltaX / unit)),
      scrollY: Math.max(-1, Math.min(1, -event.deltaY / unit)),
    });
  };

  const metaState = (event: KeyboardEvent) =>
    (event.shiftKey ? AndroidKeyEventMeta.Shift : 0) |
    (event.ctrlKey ? AndroidKeyEventMeta.Ctrl : 0) |
    (event.altKey ? AndroidKeyEventMeta.Alt : 0) |
    (event.metaKey ? AndroidKeyEventMeta.Meta : 0);

  const keyDown = (event: KeyboardEvent) => {
    // Preserve a way to leave the screen with the keyboard.
    if (event.code === "Tab" || event.isComposing) return;
    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      send({ type: "control", event: "text", text: event.key });
      return;
    }
    const keyCode =
      event.code === "Escape"
        ? AndroidKeyCode.AndroidBack
        : Object.prototype.hasOwnProperty.call(AndroidKeyCode, event.code)
          ? AndroidKeyCode[event.code as keyof typeof AndroidKeyCode]
          : undefined;
    if (keyCode === undefined) return;
    event.preventDefault();
    const repeat = Math.min(65535, (keys.get(event.code)?.repeat ?? -1) + 1);
    keys.set(event.code, { keyCode, repeat });
    send({ type: "control", event: "key", action: "down", keyCode, repeat, metaState: metaState(event) });
  };

  const keyUp = (event: KeyboardEvent) => {
    const key = keys.get(event.code);
    if (!key) return;
    event.preventDefault();
    keys.delete(event.code);
    send({ type: "control", event: "key", action: "up", keyCode: key.keyCode, repeat: 0, metaState: metaState(event) });
  };

  const contextMenu = (event: MouseEvent) => {
    if (!position(event)) return;
    event.preventDefault();
    // A touch long-press belongs to Android; only a mouse right-click means Back.
    if (event.button !== 2 || ("pointerType" in event && event.pointerType !== "mouse")) return;
    element.focus({ preventScroll: true });
    send({
      type: "control",
      event: "key",
      action: "down",
      keyCode: AndroidKeyCode.AndroidBack,
      repeat: 0,
      metaState: 0,
    });
    send({ type: "control", event: "key", action: "up", keyCode: AndroidKeyCode.AndroidBack, repeat: 0, metaState: 0 });
  };

  const visibilityChange = () => {
    if (document.hidden) release();
  };
  element.addEventListener("pointerdown", pointerDown);
  element.addEventListener("pointermove", pointerMove);
  element.addEventListener("pointerup", pointerUp);
  element.addEventListener("pointercancel", pointerUp);
  element.addEventListener("lostpointercapture", pointerUp);
  element.addEventListener("wheel", wheel, { passive: false });
  element.addEventListener("keydown", keyDown);
  element.addEventListener("keyup", keyUp);
  element.addEventListener("contextmenu", contextMenu);
  element.addEventListener("blur", release);
  window.addEventListener("blur", release);
  document.addEventListener("visibilitychange", visibilityChange);

  return () => {
    release();
    element.removeEventListener("pointerdown", pointerDown);
    element.removeEventListener("pointermove", pointerMove);
    element.removeEventListener("pointerup", pointerUp);
    element.removeEventListener("pointercancel", pointerUp);
    element.removeEventListener("lostpointercapture", pointerUp);
    element.removeEventListener("wheel", wheel);
    element.removeEventListener("keydown", keyDown);
    element.removeEventListener("keyup", keyUp);
    element.removeEventListener("contextmenu", contextMenu);
    element.removeEventListener("blur", release);
    window.removeEventListener("blur", release);
    document.removeEventListener("visibilitychange", visibilityChange);
  };
}
