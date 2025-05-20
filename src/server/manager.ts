import os from "os";
import path from "path";
import fs from "fs";
import { WebSocket } from "ws";
import { Adb, AdbServerClient, AdbShellProtocolPtyProcess, AdbTransport } from "@yume-chan/adb";
import { AdbServerNodeTcpConnector } from "@yume-chan/adb-server-node-tcp";
import Logger from "@server/utils/logger";
import { sleep } from "@shared/helpers";
import { DroidGroundConfig, FridaState } from "@shared/types";
import { WebsocketClient } from "@server/utils/types";

export class ManagerSingleton {
  private static instance: ManagerSingleton;

  private serverClient: AdbServerClient | null = null;
  private adb: Adb | null = null;
  private config: DroidGroundConfig;
  private tmpDir: string = fs.mkdtempSync(path.join(os.tmpdir(), "droidground"));
  // Bugreports
  private bugreports: Map<Adb, any> = new Map<Adb, any>();
  // WS Sessions
  public wsStreamingClients: Map<string, WebsocketClient> = new Map<string, WebsocketClient>();
  public wsTerminalSessions: Map<WebSocket, any> = new Map<WebSocket, { process: AdbShellProtocolPtyProcess }>();
  public wsFridaSessions: Map<WebSocket, FridaState | null> = new Map<WebSocket, FridaState | null>();

  private constructor() {
    // private constructor prevents direct instantiation
    const port = process.env.DG_ADB_PORT ?? "";
    this.config = {
      packageName: process.env.DG_APP_PACKAGE_NAME ?? "", // TODO: Handle case where this is not set!
      adb: {
        host: process.env.DG_ADB_HOST ?? "localhost",
        port: isNaN(port as any) || port.trim().length === 0 ? 5037 : parseInt(port),
      },
      features: {
        appManagerEnabled: !(process.env.DROIDGROUND_APP_MANAGER_DISABLED === "true"),
        bugReportEnabled: !(process.env.DROIDGROUND_BUG_REPORT_DISABLED === "true"),
        fileBrowserEnabled: !(process.env.DROIDGROUND_FILE_BROWSER_DISABLED === "true"),
        fridaEnabled: !(process.env.DROIDGROUND_FRIDA_DISABLED === "true"),
        logcatEnabled: !(process.env.DROIDGROUND_LOGCAT_DISABLED === "true"),
        rebootEnabled: !(process.env.DROIDGROUND_REBOOT_DISABLED === "true"),
        shutdownEnabled: !(process.env.DROIDGROUND_SHUTDOWN_DISABLED === "true"),
        startActivityEnabled: !(process.env.DROIDGROUND_START_ACTIVITY_DISABLED === "true"),
        startBroadcastReceiverEnabled: !(process.env.DROIDGROUND_START_RECEIVER_DISABLED === "true"),
        startServiceEnabled: !(process.env.DROIDGROUND_START_SERVICE_DISABLED === "true"),
        terminalEnabled: !(process.env.DROIDGROUND_TERMINAL_DISABLED === "true"),
      },
    };
  }

  public static getInstance(): ManagerSingleton {
    if (!ManagerSingleton.instance) {
      ManagerSingleton.instance = new ManagerSingleton();
    }
    return ManagerSingleton.instance;
  }

  public async init() {
    const connector: AdbServerNodeTcpConnector = new AdbServerNodeTcpConnector({
      host: this.config.adb.host,
      port: this.config.adb.port,
    });

    const client: AdbServerClient = new AdbServerClient(connector);
    this.serverClient = client;
    const observer = await client.trackDevices();

    observer.onDeviceAdd(devices => {
      for (const device of devices) {
        console.log("add");
        console.log(device.serial);
      }
    });

    observer.onDeviceRemove(devices => {
      for (const device of devices) {
        console.log("remove");
        console.log(device.serial);
      }
    });
  }

  private async setupAdb(): Promise<Adb> {
    const serverClient = this.serverClient as AdbServerClient;

    const devices: AdbServerClient.Device[] = await serverClient.getDevices();
    if (devices.length === 0) {
      Logger.error("No device connected");
      throw new Error("No device connected");
    }

    Logger.debug("Listing devices (and using the first one)");
    Logger.debug(devices);
    const device = devices[0];

    const transport: AdbTransport = await serverClient.createTransport(device);
    const adb: Adb = new Adb(transport);
    return adb;
  }

  public async setAdb() {
    let adb: Adb;
    while (true) {
      try {
        adb = await this.setupAdb();
        this.adb = adb;
        break;
      } catch (e) {
        Logger.error(`Error while trying to setup adb connection: ${e}`);
        Logger.error("Waiting for 5 seconds before retry...");
        await sleep(5000);
      }
    }
  }

  public async getAdb(): Promise<Adb> {
    if (!this.adb) {
      await this.setAdb();
    }
    return this.adb as Adb; // We can cast
  }

  public getConfig(): DroidGroundConfig {
    return this.config;
  }

  public getTmpDir(): string {
    return this.tmpDir;
  }
}
