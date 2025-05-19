import { v4 as uuidv4 } from "uuid";
import { AdbSocket } from "@yume-chan/adb";
import { RequestSchema, ResponseSchema } from "@server/companion/wire_pb";
import { create } from "@bufbuild/protobuf";
import Logger from "@server/utils/logger";
import { ManagerSingleton } from "@server/manager";
import { sleep } from "@shared/helpers";
import { sizeDelimitedDecodeStream, sizeDelimitedEncode } from "@bufbuild/protobuf/wire";

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

    const messageData = create(RequestSchema, {
      id,
      method,
      params: JSON.stringify(params),
    });
    const message = sizeDelimitedEncode(RequestSchema, messageData);

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

      const reader = socket.readable.getReader();

      async function* streamReader(reader: ReadableStreamDefaultReader<Uint8Array>): AsyncIterable<Uint8Array> {
        while (true) {
          const { value, done } = await reader.read();
          if (done) return;
          yield value;
        }
      }

      const readLoop = async () => {
        const iterable = streamReader(reader);

        for await (const message of sizeDelimitedDecodeStream(ResponseSchema, iterable)) {
          const { id, result } = message;
          const resolve = this.resolves.get(id);
          if (resolve) {
            resolve(JSON.parse(result));
          }
        }

        this.socket = null;
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
