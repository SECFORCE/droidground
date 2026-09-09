export interface ScrcpyPosition {
  x: number;
  y: number;
  width: number;
  height: number;
}

export type ScrcpyTouchInput = ScrcpyPosition & {
  type: "control";
  event: "touch";
  action: "down" | "move" | "up";
  pointerId: number;
  pressure: number;
};

export type ScrcpyControlMessage =
  | ScrcpyTouchInput
  | (ScrcpyPosition & { type: "control"; event: "scroll"; scrollX: number; scrollY: number })
  | { type: "control"; event: "key"; action: "down" | "up"; keyCode: number; metaState: number; repeat: number }
  | { type: "control"; event: "text"; text: string }
  | { type: "control"; event: "release" };
