import os from "os";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { execFileSync } from "child_process";
import { WebSocket } from "ws";
import { Server as HTTPServer } from "http";
import { Adb, AdbServerClient, AdbShellProtocolPtyProcess, AdbTransport } from "@yume-chan/adb";
import { ScrcpyMediaStreamConfigurationPacket } from "@yume-chan/scrcpy";
import { AdbServerNodeTcpConnector } from "@yume-chan/adb-server-node-tcp";
import Logger from "@shared/logger";
import { randomString, sleep } from "@shared/helpers";
import { DroidGroundConfig, DroidGroundTeam, FridaState, StreamMetadata, StreamingPhase } from "@shared/types";
import { AppStatus, WebsocketClient } from "@server/utils/types";
import { setupFrida } from "@server/utils/frida";
import { setupScrcpy } from "@server/utils/scrcpy";
import { AdbScrcpyClient } from "@yume-chan/adb-scrcpy";
import { getIP, parseValidUrl, safeFileExists } from "@server/utils/helpers";
import { FairQueue } from "@server/utils/queue";
import { VideoRefreshScheduler } from "@server/utils/video-refresh";

export class TeamAccessError extends Error {
  constructor(
    public readonly status: 401 | 403 | 409,
    message: string,
  ) {
    super(message);
    this.name = "TeamAccessError";
  }
}

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
  public wsExploitServerSessions: Map<WebSocket, any> = new Map<WebSocket, { teamToken: string }>();
  public wsNotificationSessions: Map<string, WebSocket> = new Map<string, WebSocket>();
  // Scrcpy
  public sharedVideoMetadata: StreamMetadata | null = null;
  public sharedConfiguration: ScrcpyMediaStreamConfigurationPacket | null = null;
  private videoRefresh = new VideoRefreshScheduler(
    () =>
      [...this.wsStreamingClients.values()].some(
        client => client.ws.readyState === WebSocket.OPEN && client.state === StreamingPhase.KEYFRAME,
      ),
    async () => {
      // Video refresh is internal stream maintenance; input access remains feature-gated.
      await this.scrcpyClient?.controller?.resetVideo();
    },
    error => Logger.error({ err: error }, "Failed to refresh the video stream"),
  );
  // Exploit apps (keeping a list in order to quickly delete them on reset)
  public exploitApps: string[] = [];
  private installingPackages = new Set<string>();
  // Exploit App Run Queue
  public queue;

  private constructor() {
    // private constructor prevents direct instantiation
    const port: any = process.env.DROIDGROUND_ADB_PORT ?? "";
    const serialEnv: any = process.env.DROIDGROUND_ADB_SERIAL ?? "";
    const adbSerial = serialEnv.trim().length === 0 ? undefined : serialEnv.trim();
    const exploitAppDuration: any = process.env.DROIDGROUND_EXPLOIT_APP_DURATION ?? "";
    const exploitAppmaxSizeEnv: any = process.env.DROIDGROUND_EXPLOIT_APP_MAX_SIZE ?? "";
    const exploitAppMaxSize: number =
      isNaN(exploitAppmaxSizeEnv) || exploitAppmaxSizeEnv.trim().length === 0 ? 50 : parseInt(exploitAppmaxSizeEnv);
    // Check if IP address should be displayed
    const ipStatic = process.env.DROIDGROUND_IP_STATIC ?? undefined;
    const iface = process.env.DROIDGROUND_IP_IFACE ?? "";
    const ipAddress = ipStatic && ipStatic.length > 0 ? ipStatic : getIP(iface); // Either an empty string or the IP address
    const backendPort = process.env.DROIDGROUND_PORT || 4242;
    // Check team-mode
    const teamNumEnv: any = process.env.DROIDGROUND_NUM_TEAMS ?? "";
    const teamNum: number = isNaN(teamNumEnv) || teamNumEnv.trim().length === 0 ? 0 : parseInt(teamNumEnv);
    const teamTokens = this.setupTeamTokens(teamNum);
    const teams: DroidGroundTeam[] = teamTokens.map(t => ({ token: t, exploitApps: [] }));
    // Exploit App Run Queue
    this.queue = new FairQueue<string>({
      concurrency: 1,
      maxPerUserQueue: 1,
      maxTotalQueue: teamNum !== 0 ? teamNum : 10, // Size of the queue is 10 by default if no teams
    });
    // Config
    this.config = {
      packageName: process.env.DROIDGROUND_APP_PACKAGE_NAME ?? "",
      adb: {
        host: process.env.DROIDGROUND_ADB_HOST ?? "localhost",
        port: isNaN(port) || port.trim().length === 0 ? 5037 : parseInt(port),
        serial: adbSerial,
      },
      features: {
        basePath: process.env.DROIDGROUND_BASE_PATH ?? "",
        restartAppEnabled: !(process.env.DROIDGROUND_RESTART_APP_DISABLED === "true"),
        appManagerEnabled: !(process.env.DROIDGROUND_APP_MANAGER_DISABLED === "true"),
        bugReportEnabled: !(process.env.DROIDGROUND_BUG_REPORT_DISABLED === "true"),
        fileBrowserEnabled: !(process.env.DROIDGROUND_FILE_BROWSER_DISABLED === "true"),
        fridaEnabled: !(process.env.DROIDGROUND_FRIDA_DISABLED === "true"),
        logcatEnabled: !(process.env.DROIDGROUND_LOGCAT_DISABLED === "true"),
        rebootEnabled: process.env.DROIDGROUND_REBOOT_ENABLED === "true",
        shutdownEnabled: process.env.DROIDGROUND_SHUTDOWN_ENABLED === "true",
        startActivityEnabled: !(process.env.DROIDGROUND_START_ACTIVITY_DISABLED === "true"),
        startBroadcastReceiverEnabled: !(process.env.DROIDGROUND_START_RECEIVER_DISABLED === "true"),
        startServiceEnabled: !(process.env.DROIDGROUND_START_SERVICE_DISABLED === "true"),
        terminalEnabled: !(process.env.DROIDGROUND_TERMINAL_DISABLED === "true"),
        resetEnabled: !(process.env.DROIDGROUND_RESET_DISABLED === "true"),
        scrcpyControlEnabled: process.env.DROIDGROUND_SCRCPY_CONTROL_ENABLED === "true",
        teamModeEnabled: teamNum > 0 || teamNum === -1,
        unlimitedTeams: teamNum === -1,
        fridaType: process.env.DROIDGROUND_FRIDA_TYPE === "full" ? "full" : "jail",
        fridaInjection: process.env.DROIDGROUND_FRIDA_INJECTION === "gadget" ? "gadget" : "server",
        exploitAppDuration:
          isNaN(exploitAppDuration) || exploitAppDuration.trim().length === 0 ? 10 : parseInt(exploitAppDuration),
        exploitAppMaxSize: exploitAppMaxSize,
        ipAddress: `${ipAddress}:${backendPort}`,
        logoLink: parseValidUrl(process.env.DROIDGROUND_LOGO_LINK ?? ""),
      },
      teams: teams,
      debugToken: crypto.randomBytes(64).toString("hex"),
    };

    Logger.info(`Debug token is: ${this.config.debugToken}`);
    if (teamNum > 0) {
      Logger.info(`Team mode is enabled, ${teamNum} tokens are available:`);
      for (let i = 0; i < teamNum; i++) {
        Logger.info(`\tTeam #${i}: ${teamTokens[i]}`);
      }
    }
  }

  public static getInstance(): ManagerSingleton {
    if (!ManagerSingleton.instance) {
      ManagerSingleton.instance = new ManagerSingleton();
    }
    return ManagerSingleton.instance;
  }

  public async init(httpServer: HTTPServer) {
    try {
      Logger.debug("Singleton init...");
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

        const requestedSerial = this.config.adb.serial;
        if (requestedSerial) {
          const addedSerials = _devices.map(device => device.serial);
          if (!addedSerials.includes(requestedSerial)) {
            Logger.debug(`Ignoring added devices because serial '${requestedSerial}' was not included.`);
            return;
          }
        }

        await this.setupAdb();
        await this.setCtf();

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
        Logger.debug("Singleton init done!");
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
            this.scrcpyClient = null;
          }
        }
      });
    } catch (e) {
      if (e instanceof AggregateError) {
        Logger.error("Multiple errors occurred while setting up the application:");
        for (const specificError of e.errors) {
          Logger.error(`\t${specificError}`);
        }
      } else {
        Logger.error(`Error while setting up the application: ${e}`);
      }

      Logger.error("Check if the 'adb' server is up & running and then restart the app.");
      process.exit(1);
    }
  }

  private async setupAdb() {
    const serverClient = this.serverClient as AdbServerClient;
    const devices: AdbServerClient.Device[] = await serverClient.getDevices();
    if (devices.length === 0) {
      Logger.error("No device connected");
      throw new Error("No device connected");
    }

    const serial = this.config.adb.serial;
    let device: AdbServerClient.Device | undefined;
    if (serial) {
      Logger.debug(`Looking for device with serial '${serial}'`);
      device = devices.find(d => d.serial === serial);
      if (!device) {
        Logger.error(`ADB device with serial '${serial}' not found`);
        Logger.debug(`Connected devices: ${JSON.stringify(devices)}`);
        throw new Error(`ADB device with serial '${serial}' not found`);
      }
    } else {
      Logger.debug("Listing devices (and using the first one)");
      Logger.debug(devices);
      device = devices[0];
    }

    this.device = device;

    await serverClient.waitFor(device, "device");

    const transport: AdbTransport = await serverClient.createTransport(device);
    Logger.debug("Transport created.");
    const adb: Adb = new Adb(transport);
    this.adb = adb;
  }

  private setupTeamTokens(numTeams: number): string[] {
    const tokens: string[] = [];
    for (let i = 0; i < numTeams; i++) {
      const teamTokenEnv: any = process.env[`DROIDGROUND_TEAM_TOKEN_${i + 1}`] ?? "";
      const teamToken = teamTokenEnv.trim().length === 0 ? randomString(32) : teamTokenEnv.trim();
      if (tokens.includes(teamToken)) throw new Error("Each team must have a unique Team Token.");
      tokens.push(teamToken);
    }
    return tokens;
  }

  public addTeam(): string {
    let teamToken = "";
    while (true) {
      teamToken = randomString(32);
      const el = this.config.teams.find(t => t.token === teamToken);
      if (el === undefined) {
        break;
      }
    }
    this.config.teams.push({ token: teamToken, exploitApps: [] });
    return teamToken;
  }

  private async checkPackage() {
    const adb = this.adb as Adb;
    const res = await adb.subprocess.noneProtocol.spawnWaitText(`pm list packages | grep ${this.config.packageName}`);

    const lines = res.trim().split("\n");

    if (lines.length !== 1 || lines[0].length === 0) {
      Logger.error(`Invalid or not installed package name: '${this.config.packageName}'`);
      process.exit(1);
    }
  }

  public async setAdb() {
    Logger.debug("Adb setup....");
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
    Logger.debug("Adb setup done!");
  }

  // Only run this after setup to ensure Adb is set
  public async waitBootCompletion() {
    Logger.debug("Waiting for boot completion...");
    while (true) {
      const bootCompletedProp = await (this.adb as Adb).getProp("sys.boot_completed");
      const bootCompleted = bootCompletedProp.trim() === "1";
      if (bootCompleted) {
        Logger.info("Boot completed.");
        break;
      } else {
        Logger.error("Boot is not completed yet, waiting 5 seconds before checking again...");
        await sleep(5000);
      }
    }
  }

  public setScrcpyClient(scrcpyClient: AdbScrcpyClient<any>) {
    this.scrcpyClient = scrcpyClient;
  }

  public getScrcpyController() {
    return this.config.features.scrcpyControlEnabled ? this.scrcpyClient?.controller : undefined;
  }

  public requestVideoRefresh() {
    this.videoRefresh.request();
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

  public async runAppByPackageName(packageName: string) {
    const adb = await this.getAdb();
    // Force close the app
    await adb.subprocess.noneProtocol.spawnWait(`am force-stop ${packageName} 1`);
    // And then reopen it

    // Try with resolved activity first
    const activityToLaunch = (
      await adb.subprocess.noneProtocol.spawnWaitText(`cmd package resolve-activity --brief ${packageName} | tail -n 1`)
    ).trim();

    if (activityToLaunch.length > 0) {
      await adb.subprocess.noneProtocol.spawnWait(`am start ${activityToLaunch}`);
    } else {
      // Otherwise go with monkey
      await adb.subprocess.noneProtocol.spawnWait(`monkey -p ${packageName} 1`);
    }
  }

  public async runTargetApp() {
    await this.runAppByPackageName(this.config.packageName);
  }

  public async setCtf(): Promise<boolean> {
    const initDFolder = process.env.DROIDGROUND_INIT_SCRIPTS_FOLDER ?? "/init.d";
    const setupScript = path.resolve(initDFolder, "setup.sh");
    if (!safeFileExists(setupScript)) {
      Logger.error(`setup.sh script missing in the ${initDFolder}`);
      return false;
    }

    Logger.info("Running setup.sh script...");
    const setupArgs = this.config.adb.serial ? [this.config.adb.serial] : [];
    const scriptOutput = execFileSync(setupScript, setupArgs, {
      cwd: process.env.DROIDGROUND_INIT_SCRIPTS_FOLDER,
      stdio: "pipe",
      encoding: "utf-8",
    })
      .toString()
      .trim();
    Logger.info(`setup.sh output: ${scriptOutput}`);
    // Check if the app is installed, otherwise stop DroidGround
    await this.checkPackage();

    return true;
  }

  public async resetCtf(): Promise<boolean> {
    for await (const appToDelete of this.exploitApps) {
      const uninstallRes = await this.adb!.subprocess.noneProtocol.spawnWaitText(`pm uninstall ${appToDelete}`);
      Logger.info(`App ${appToDelete} uninstall result: ${uninstallRes}`);
    }

    // Unlink all exploit apps
    this.exploitApps = [];
    for (const team of this.config.teams) {
      team.exploitApps = [];
    }

    const initDFolder = process.env.DROIDGROUND_INIT_SCRIPTS_FOLDER ?? "/init.d";
    const resetScript = path.resolve(initDFolder, "reset.sh");
    if (safeFileExists(resetScript)) {
      const resetArgs = this.config.adb.serial ? [this.config.adb.serial] : [];
      const scriptOutput = execFileSync(resetScript, resetArgs, {
        cwd: process.env.DROIDGROUND_INIT_SCRIPTS_FOLDER,
        stdio: "pipe",
        encoding: "utf-8",
      })
        .toString()
        .trim();
      Logger.info(`reset.sh output: ${scriptOutput}`);
      return true;
    } else {
      Logger.error(`reset.sh script missing in the ${initDFolder}`);
      return false;
    }
  }

  public getTeamTokens(): string[] {
    return this.config.teams.map(t => t.token);
  }

  public isTeamTokenValid(teamToken: unknown): teamToken is string {
    return typeof teamToken === "string" && teamToken.length > 0 && this.getTeamTokens().includes(teamToken);
  }

  private assertPackageOwner(packageName: string, teamToken?: string) {
    if (!this.config.features.teamModeEnabled) return;
    if (!this.isTeamTokenValid(teamToken)) {
      throw new TeamAccessError(401, "Missing or invalid Team Token.");
    }
    if (this.config.teams.some(team => team.token !== teamToken && team.exploitApps.includes(packageName))) {
      throw new TeamAccessError(403, "This app is not available to your team.");
    }
  }

  public assertAppAccess(packageName: string, teamToken?: string) {
    this.assertPackageOwner(packageName, teamToken);
    if (
      !this.exploitApps.includes(packageName) ||
      (this.config.features.teamModeEnabled && !this.getExploitAppsLinkedToTeam(teamToken!).includes(packageName))
    ) {
      throw new TeamAccessError(403, "This app is not available to your team.");
    }
  }

  public reserveAppInstallation(packageName: string, teamToken?: string): () => void {
    this.assertPackageOwner(packageName, teamToken);
    if (packageName === this.config.packageName) {
      throw new TeamAccessError(403, "The target app cannot be registered as a team app.");
    }
    if (this.installingPackages.has(packageName)) {
      throw new TeamAccessError(409, "An installation for this package is already in progress.");
    }
    this.installingPackages.add(packageName);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.installingPackages.delete(packageName);
    };
  }

  public registerInstalledApp(packageName: string, teamToken?: string) {
    this.assertPackageOwner(packageName, teamToken);
    if (this.config.features.teamModeEnabled) this.linkExploitAppToTeam(teamToken!, packageName);
    if (!this.exploitApps.includes(packageName)) this.exploitApps.push(packageName);
  }

  public linkExploitAppToTeam(teamToken: string, exploitApp: string) {
    this.assertPackageOwner(exploitApp, teamToken);
    const team = this.config.teams.find(team => team.token === teamToken);
    if (!team) throw new TeamAccessError(401, "Missing or invalid Team Token.");
    if (!team.exploitApps.includes(exploitApp)) team.exploitApps.push(exploitApp);
  }

  public getExploitAppsLinkedToTeam(teamToken: string): string[] {
    return this.config.teams.find(t => t.token === teamToken)?.exploitApps ?? [];
  }
}
