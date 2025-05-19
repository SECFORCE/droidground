import { v4 as uuidv4 } from "uuid";
import { AdbSocket } from "@yume-chan/adb";
import * as wire from "@server/companion/wire";
import Logger from "@server/utils/logger";
import { ManagerSingleton } from "@server/manager";
import { sleep } from "@shared/helpers";

type PlainObj<T> = { [name: string]: T };

export class CompanionClient {
  private static instance: CompanionClient;

  private socket: AdbSocket | null = null;
  private resolves: Map<string, (value?: any) => void> = new Map();

  private constructor() {
    // private constructor prevents direct instantiation
  }

  public static getInstance(): CompanionClient {
    if (!CompanionClient.instance) {
      CompanionClient.instance = new CompanionClient();
    }
    return CompanionClient.instance;
  }

  async sendMessage(method: string, params: PlainObj<any> = {}) {
    if (!this.socket) {
      await this.connect();
    }

    const socket = this.socket as AdbSocket;
    const id = uuidv4();

    const message = wire.com.secforce.droidground.Request.encodeDelimited({
      id,
      method,
      params: JSON.stringify(params),
    }).finish(); // Uint8Array

    const writer = socket.writable.getWriter();
    await writer.write(message);
    writer.releaseLock();

    return new Promise(resolve => {
      this.resolves.set(id, resolve);
    });
  }

  private async connect(tryStart = true) {
    Logger.debug("Connecting to DroidGround Companion");
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const socket = await adb.createSocket("localabstract:droidground");
      this.socket = socket;

      let buf = new Uint8Array(0);
      const reader = socket.readable.getReader();

      const readLoop = async () => {
        while (true) {
          const { value: chunk, done } = await reader.read();
          if (done) {
            this.socket = null;
            break;
          }

          // Append chunk to buffer
          const newBuf = new Uint8Array(buf.length + chunk.length);
          newBuf.set(buf);
          newBuf.set(chunk, buf.length);
          buf = newBuf;

          try {
            const message = wire.com.secforce.droidground.Response.decodeDelimited(buf);
            buf = new Uint8Array(0);
            const { id, result } = message;

            const resolve = this.resolves.get(id);
            if (resolve) {
              resolve(JSON.parse(result));
            }
          } catch {
            // Likely incomplete buffer, wait for next chunk
          }
        }
      };

      readLoop(); // Start reading without awaiting so we don't block connect()
    } catch (e) {
      if (tryStart) {
        await this.push();
        await this.start();
        while (true) {
          const isRunning = await this.isRunning();
          if (isRunning) {
            break;
          } else {
            await sleep(500);
          }
        }
        await this.connect(false);
      }
    }
  }

  private isRunning = async () => {
    const adb = await ManagerSingleton.getInstance().getAdb();
    const result = await adb.subprocess.noneProtocol.spawnWaitText("cat /proc/net/unix");
    return result.includes("@droidground");
  };

  private async push() {
    Logger.warn("TODO. Pushing app to /data/local/tmp");
  }

  private async start() {
    Logger.debug("Starting DroidGround Companion");
    const adb = await ManagerSingleton.getInstance().getAdb();
    await adb.subprocess.noneProtocol.spawn(
      "CLASSPATH=/data/local/tmp/droidground-companion.dex app_process /system/bin com.secforce.droidground.Server",
    );

    Logger.debug("DroidGround Companion started!");
  }
}
