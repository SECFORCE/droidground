import type { ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import type { ScrcpyVideoDecoder } from "@yume-chan/scrcpy-decoder-tinyh264";
import type { WSMessageType, WSMetadata } from "@shared/types";

const textDecoder = new TextDecoder();

export function parseVideoMessage(buffer: ArrayBuffer) {
  if (buffer.byteLength < 4) throw new Error("Truncated video message");
  const metadataLength = new DataView(buffer).getUint32(0);
  if (metadataLength > buffer.byteLength - 4) throw new Error("Truncated video metadata");
  const bytes = new Uint8Array(buffer);
  const { type, ...metadata } = JSON.parse(textDecoder.decode(bytes.subarray(4, 4 + metadataLength)));
  // The decoder can read the received frame directly, without copying its entire payload.
  return { type: type as WSMessageType, metadata: metadata as WSMetadata, data: bytes.subarray(4 + metadataLength) };
}

type Decoder = Pick<ScrcpyVideoDecoder, "writable" | "dispose" | "framesRendered" | "framesSkipped">;
export const MAX_PENDING_VIDEO_FRAMES = 12;

export class LiveVideoDecoder {
  private decoder?: Decoder;
  private writer?: ReturnType<Decoder["writable"]["getWriter"]>;
  private configuration?: Uint8Array;
  private submitted = 0;
  private waitingForKeyframe = true;
  private disposed = false;

  constructor(
    private createDecoder: () => Decoder,
    private onError: (error: unknown) => void,
  ) {}

  private reset() {
    const decoder = this.decoder;
    const writer = this.writer;
    this.decoder = undefined;
    this.writer = undefined;
    this.submitted = 0;
    this.waitingForKeyframe = true;
    // Let an in-progress configuration finish before disposing the software decoder.
    if (writer)
      void writer
        .abort()
        .catch(() => {})
        .then(() => decoder?.dispose());
  }

  private start() {
    if (!this.configuration || this.disposed) return;
    try {
      this.decoder = this.createDecoder();
      const decoder = this.decoder;
      this.writer = this.decoder.writable.getWriter();
      void this.writer.closed.catch(error => this.failed(decoder, error));
      this.write({ type: "configuration", data: this.configuration });
    } catch (error) {
      this.reset();
      this.onError(error);
    }
  }

  private failed(decoder: Decoder | undefined, error: unknown) {
    if (!decoder || decoder !== this.decoder || this.disposed) return;
    this.reset();
    this.onError(error);
  }

  private write(packet: ScrcpyMediaStreamPacket) {
    const decoder = this.decoder;
    void this.writer?.write(packet).catch(error => this.failed(decoder, error));
  }

  configure(data: Uint8Array) {
    if (this.disposed) return;
    this.configuration = data;
    this.reset();
    this.start();
  }

  push(packet: ScrcpyMediaStreamPacket, visible = true) {
    if (this.disposed || packet.type !== "data") return;
    if (!visible) {
      if (this.decoder) this.reset();
      return;
    }
    if (
      this.decoder &&
      this.submitted - this.decoder.framesRendered - this.decoder.framesSkipped >= MAX_PENDING_VIDEO_FRAMES
    ) {
      // A slow decoder must catch up to the live stream, not replay a growing backlog.
      this.reset();
    }
    if (this.waitingForKeyframe && !packet.keyframe) return;
    if (!this.decoder) this.start();
    if (!this.decoder) return;
    this.waitingForKeyframe = false;
    this.submitted++;
    this.write(packet);
  }

  dispose() {
    this.disposed = true;
    this.reset();
    this.configuration = undefined;
  }
}
