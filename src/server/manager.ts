import os from "os";
import path from "path";
import fs from "fs";
import { WebSocket } from "ws";
import { Server as HTTPServer } from "http";
import { Adb, AdbServerClient, AdbShellProtocolPtyProcess, AdbTransport } from "@yume-chan/adb";
import { AdbServerNodeTcpConnector } from "@yume-chan/adb-server-node-tcp";
import Logger from "@server/utils/logger";
import { sleep } from "@shared/helpers";
import { DroidGroundConfig, FridaState, StreamMetadata } from "@shared/types";
import { AppStatus, WebsocketClient } from "@server/utils/types";
import { setupFrida } from "./utils/frida";
import { ScrcpyMediaStreamConfigurationPacket } from "@yume-chan/scrcpy";
import { setupScrcpy } from "./utils/scrcpy";
import { AdbScrcpyClient } from "@yume-chan/adb-scrcpy";
import { execSync } from "child_process";

export class ManagerSingleton {
  private static instance: ManagerSingleton;

  private appStatus: AppStatus = AppStatus.INIT_PHASE;
  private httpServer: HTTPServer | null = null;
  private scrcpyClient: AdbScrcpyClient<any> | null = null;
  private serverClient: AdbServerClient | null = null;
  private adb: Adb | null = null;
  private device: AdbServerClient.Device | null = null;
  private config: DroidGroundConfig;
  private tmpDir: string = fs.mkdtempSync(path.join(os.tmpdir(), "droidground"));
  // Bugreports
  private bugreports: Map<Adb, any> = new Map<Adb, any>();
  // WS Sessions
  public wsStreamingClients: Map<string, WebsocketClient> = new Map<string, WebsocketClient>();
  public wsTerminalSessions: Map<WebSocket, any> = new Map<WebSocket, { process: AdbShellProtocolPtyProcess }>();
  public wsFridaSessions: Map<WebSocket, FridaState | null> = new Map<WebSocket, FridaState | null>();
  // Scrcpy
  public sharedVideoMetadata: StreamMetadata | null = null;
  public sharedConfiguration: ScrcpyMediaStreamConfigurationPacket | null = null;

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
        fridaType: process.env.DROIDGROUND_FRIDA_TYPE === "full" ? "full" : "jail",
      },
    };
  }

  public static getInstance(): ManagerSingleton {
    if (!ManagerSingleton.instance) {
      ManagerSingleton.instance = new ManagerSingleton();
    }
    return ManagerSingleton.instance;
  }

  public async init(httpServer: HTTPServer) {
    this.httpServer = httpServer;
    const connector: AdbServerNodeTcpConnector = new AdbServerNodeTcpConnector({
      host: this.config.adb.host,
      port: this.config.adb.port,
    });

    const client: AdbServerClient = new AdbServerClient(connector);
    this.serverClient = client;
    const observer = await client.trackDevices();

    observer.onDeviceAdd(async _devices => {
      // Let's do this only when the device is disconnected and everything needs to be setup again
      if (this.appStatus !== AppStatus.DISCONNECTED_PHASE) {
        return;
      }

      if (!this.httpServer) {
        Logger.error("Missing httpServer, cannot stop the server");
        return;
      }

      await this.setupAdb();
      this.setCtf();
      if (this.getConfig().features.fridaEnabled) {
        await setupFrida();
      }

      const host = process.env.DROIDGROUND_HOST || "0.0.0.0";
      const port = process.env.DROIDGROUND_PORT || 4242;
      this.httpServer.listen(Number(port), host, () => {
        Logger.info(`Restarting DroidGround on http://${host}:${port}.`);
      });
      await setupScrcpy();
      this.appStatus = AppStatus.RUNNING_PHASE;
    });

    observer.onDeviceRemove(async devices => {
      for (const device of devices) {
        Logger.debug(`Device with serial ${device.serial} disconnected`);
        if (!this.httpServer) {
          Logger.error("Missing httpServer, cannot stop the server");
          continue;
        }

        if (device.serial === this.device?.serial) {
          Logger.info("Stopping HTTP Server.");
          this.httpServer.close();
          this.appStatus = AppStatus.DISCONNECTED_PHASE;
          this.adb = null;
          await this.scrcpyClient?.close();
        }
      }
    });
  }

  private async setupAdb() {
    const serverClient = this.serverClient as AdbServerClient;

    await serverClient.waitFor({ usb: true, tcp: true }, "device");
    const devices: AdbServerClient.Device[] = await serverClient.getDevices();
    if (devices.length === 0) {
      Logger.error("No device connected");
      throw new Error("No device connected");
    }

    Logger.debug("Listing devices (and using the first one)");
    Logger.debug(devices);
    const device = devices[0];

    this.device = device;

    const transport: AdbTransport = await serverClient.createTransport(device);
    Logger.debug("Transport created.");
    const adb: Adb = new Adb(transport);
    this.adb = adb;
  }

  public async setAdb() {
    while (true) {
      try {
        await this.setupAdb();
        break;
      } catch (e) {
        Logger.error(`Error while trying to setup adb connection: ${e}`);
        Logger.error("Waiting for 5 seconds before retry...");
        await sleep(5000);
      }
    }
    this.appStatus = AppStatus.RUNNING_PHASE;
  }

  public setScrcpyClient(scrcpyClient: AdbScrcpyClient<any>) {
    this.scrcpyClient = scrcpyClient;
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

  public async runTargetApp() {
    const adb = await this.getAdb();
    // Force close the app
    await adb.subprocess.noneProtocol.spawnWait(`am force-stop ${this.config.packageName} 1`);
    // And then reopen it
    await adb.subprocess.noneProtocol.spawnWait(`monkey -p ${this.config.packageName} 1`);
  }

  public setCtf() {
    const initDFolder = process.env.DG_INIT_SCRIPTS_FOLDER ?? "";
    const setupScript = path.resolve(initDFolder, "setup.sh");
    execSync(setupScript, { cwd: process.env.DG_INIT_SCRIPTS_FOLDER }).toString().trim();
  }

  public resetCtf() {
    const initDFolder = process.env.DG_INIT_SCRIPTS_FOLDER ?? "";
    const setupScript = path.resolve(initDFolder, "reset.sh");
    execSync(setupScript, { cwd: process.env.DG_INIT_SCRIPTS_FOLDER }).toString().trim();
  }
}
