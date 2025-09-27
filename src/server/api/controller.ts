// Node.js imports
import path from "path";
import fs from "fs/promises";

// Package imports
import { RequestHandler, Request, Response } from "express";
import { ReadableStream } from "@yume-chan/stream-extra";

// Local imports
import Logger from "@shared/logger";
import { ManagerSingleton } from "@server/manager";
import {
  ActionResponse,
  BugreportzStatusResponse,
  CompanionPackageInfos,
  DeviceInfoResponse,
  DroidGroundFeaturesResponse,
  FridaLibraryResponse,
  GetFilesRequest,
  GetFilesResponse,
  IGenericErrRes,
  IGenericResultRes,
  StartActivityRequest,
  StartBroadcastRequest,
  StartExploitAppRequest,
  StartServiceRequest,
} from "@shared/api";
import {
  buildExtra,
  parseLsAlOutput,
  safeFileExists,
  shellEscape,
  versionNumberToCodename,
} from "@server/utils/helpers";
import { capitalize, sleep } from "@shared/helpers";
import { CompanionClient } from "@server/companion";
import { BUGREPORT_FILENAME, DEFAULT_UPLOAD_FOLDER, SECOND } from "@server/config";
import { CompanionAttackSurface, CompanionAttackSurfaceResponse } from "@server/utils/types";
import { loadFridaLibrary } from "@server/utils/frida";

class APIController {
  features: RequestHandler = async (req: Request, res: Response<DroidGroundFeaturesResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const droidGroundConfig = ManagerSingleton.getInstance().getConfig();
      res.json(droidGroundConfig.features).end();
    } catch (error: any) {
      Logger.error(`Error getting features config: ${error}`);
      res.status(500).json({ error: "An error occurred while getting features config." }).end();
    }
  };

  reset: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const singleton = ManagerSingleton.getInstance();
      const resetDone = await singleton.resetCtf();
      if (!resetDone) {
        res.status(500).json({ error: "An error occurred while resetting the CTF" }).end();
        return;
      }

      await singleton.runTargetApp();
      res.json({ result: "CTF correctly reset" }).end();
    } catch (error: any) {
      Logger.error(`Error resetting the CTF: ${error}`);
      res.status(500).json({ error: "An error occurred while resetting the CTF" }).end();
    }
  };

  restartApp: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      await ManagerSingleton.getInstance().runTargetApp();
      res.json({ result: "Target app correctly restarted" }).end();
    } catch (error: any) {
      Logger.error(`Error restarting target app: ${error}`);
      res.status(500).json({ error: "An error occurred while restarting the target app." }).end();
    }
  };

  info: RequestHandler = async (req: Request, res: Response<DeviceInfoResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const versionResult = await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.build.version.release");
      const processorResult = await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.product.cpu.abi");
      const deviceTypeResult = await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.kernel.qemu");
      const modelResult = await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.product.model");
      const manufacturerResult = await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.product.manufacturer");

      const codename = versionNumberToCodename(versionResult.trim());

      const response: DeviceInfoResponse = {
        version: `${versionResult.trim()} (${codename})`,
        deviceType: deviceTypeResult.trim() === "1" ? "Emulator" : "Device",
        architecture: processorResult.trim(),
        model: `${capitalize(manufacturerResult.trim())} ${modelResult.trim()}`,
      };
      res.json(response).end();
    } catch (error: any) {
      Logger.error(`Error getting info: ${error}`);
      res.status(500).json({ error: "An error occurred while getting device info." }).end();
    }
  };

  getAttackSurface: RequestHandler = async (req: Request, res: Response<CompanionAttackSurface | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const client = CompanionClient.getInstance();
      const config = ManagerSingleton.getInstance().getConfig();
      const bufRes = await client.sendMessage<CompanionAttackSurfaceResponse>("getAttackSurfaces", {
        packageNames: [config.packageName],
      });
      const attackSurface = bufRes.attackSurfaces[config.packageName];
      res.json(attackSurface).end();
    } catch (error: any) {
      Logger.error(`Error getting attack surface: ${error}`);
      res.status(500).json({ error: "An error occurred while getting the attack surface." }).end();
    }
  };

  startActivity: RequestHandler = async (req: Request, res: Response<ActionResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const body = req.body as StartActivityRequest;
      const config = ManagerSingleton.getInstance().getConfig();
      const client = CompanionClient.getInstance();
      const bufRes = await client.sendMessage<CompanionAttackSurfaceResponse>("getAttackSurfaces", {
        packageNames: [config.packageName],
      });
      const exportedActivities = bufRes.attackSurfaces[config.packageName].activities;

      if (!exportedActivities.includes(body.activity)) {
        res.status(400).json({ error: "This activity is not exported by the target app" }).end();
        return;
      }

      const parts: string[] = ["am start"];

      /*
      // User
      if (body.user !== undefined) {
        parts.push(`--user ${shellEscape(body.user.toString())}`);
      }
      */

      // Action
      if (body.action) {
        parts.push(`-a ${shellEscape(body.action)}`);
      }

      // Data URI
      if (body.dataUri) {
        parts.push(`-d ${shellEscape(body.dataUri)}`);
      }

      // MIME Type
      if (body.mimeType) {
        parts.push(`-t ${shellEscape(body.mimeType)}`);
      }

      // Categories
      if (body.categories) {
        for (const category of body.categories) {
          parts.push(`-c ${shellEscape(category)}`);
        }
      }

      // Flags
      if (body.flags !== undefined && body.flags !== null) {
        parts.push(`-f ${shellEscape(body.flags.toString())}`);
      }

      // Extras
      if (body.extras) {
        for (const extra of body.extras) {
          parts.push(...buildExtra(extra));
        }
      }

      // Activity
      const activityName = `${config.packageName}/${body.activity}`;
      parts.push(`-n ${shellEscape(activityName)}`);

      const command = parts.join(" ");
      Logger.debug(`Running command: "${command}"`);
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(command);
      res.json({ command, result }).end();
    } catch (error: any) {
      Logger.error(`Error starting activity: ${error}`);
      res.status(500).json({ error: "An error occurred while starting the activity." }).end();
    }
  };

  startBroadcast: RequestHandler = async (req: Request, res: Response<ActionResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const body = req.body as StartBroadcastRequest;
      const config = ManagerSingleton.getInstance().getConfig();
      const client = CompanionClient.getInstance();
      const bufRes = await client.sendMessage<CompanionAttackSurfaceResponse>("getAttackSurfaces", {
        packageNames: [config.packageName],
      });
      const exportedReceiver = bufRes.attackSurfaces[config.packageName].receivers;

      if (!exportedReceiver.includes(body.receiver)) {
        res.status(400).json({ error: "This receiver is not exported by the target app" }).end();
        return;
      }

      const parts: string[] = ["am broadcast"];

      /*
      // User
      if (body.user !== undefined) {
        parts.push(`--user ${shellEscape(body.user.toString())}`);
      }
      */

      // Action
      if (body.action) {
        parts.push(`-a ${shellEscape(body.action)}`);
      }

      // Receiver
      parts.push(`-n ${shellEscape(`${config.packageName}/${body.receiver}`)}`);

      // Extras
      if (body.extras) {
        for (const extra of body.extras) {
          parts.push(...buildExtra(extra));
        }
      }

      const command = parts.join(" ");
      Logger.debug(`Running command: "${command}"`);
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(command);
      res.json({ command, result }).end();
    } catch (error: any) {
      Logger.error(`Error starting broadcast: ${error}`);
      res.status(500).json({ error: "An error occurred while starting the broadcast." }).end();
    }
  };

  startService: RequestHandler = async (req: Request, res: Response<ActionResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const body = req.body as StartServiceRequest;
      const config = ManagerSingleton.getInstance().getConfig();
      const client = CompanionClient.getInstance();
      const bufRes = await client.sendMessage<CompanionAttackSurfaceResponse>("getAttackSurfaces", {
        packageNames: [config.packageName],
      });
      const exportedServices = bufRes.attackSurfaces[config.packageName].services;

      if (!exportedServices.includes(body.service)) {
        res.status(400).json({ error: "This service is not exported by the target app" }).end();
        return;
      }

      const parts: string[] = ["am startservice"];

      /*
      // User
      if (body.user !== undefined) {
        parts.push(`--user ${shellEscape(body.user.toString())}`);
      }
      */

      // Action
      if (body.action) {
        parts.push(`-a ${shellEscape(body.action)}`);
      }

      // Extras
      if (body.extras) {
        for (const extra of body.extras) {
          parts.push(...buildExtra(extra));
        }
      }

      // Service
      parts.push(`-n ${shellEscape(`${config.packageName}/${body.service}`)}`);

      const command = parts.join(" ");
      Logger.debug(`Running command: "${command}"`);
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(command);
      res.json({ command, result }).end();
    } catch (error: any) {
      Logger.error(`Error starting service: ${error}`);
      res.status(500).json({ error: "An error occurred while starting the service." }).end();
    }
  };

  closeDialogs: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS`);
      res.json({ result: "System dialogs closed" }).end();
    } catch (error: any) {
      Logger.error(`Error closing system dialogs: ${error}`);
      res.status(500).json({ error: "An error occurred while closing system dialogs." }).end();
    }
  };

  shutdown: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot -p`);
      res.json({ result: "Device shutted down" }).end();
    } catch (error: any) {
      Logger.error(`Error shutting down the device: ${error}`);
      res.status(500).json({ error: "An error occurred while shutting down the device." }).end();
    }
  };

  reboot: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot`);
      res.json({ result: "Device rebooted" }).end();
    } catch (error: any) {
      Logger.error(`Error rebooting the device: ${error}`);
      res.status(500).json({ error: "An error occurred while rebooting the device." }).end();
    }
  };

  dumpLogcat: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(`logcat -d -t 500`);
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error(`Error dumping logcat: ${error}`);
      res.status(500).json({ error: "An error occurred while dumping logcat." }).end();
    }
  };

  clearLogcat: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawn(`logcat -c`);
      res.json({ result: "Logcat cleared" }).end();
    } catch (error: any) {
      Logger.error(`Error clearing logcat: ${error}`);
      res.status(500).json({ error: "An error occurred while clearing logcat." }).end();
    }
  };

  files: RequestHandler = async (req: Request, res: Response<GetFilesResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const body = req.body as GetFilesRequest;
      const path = body.path;

      const adb = await ManagerSingleton.getInstance().getAdb();
      const sync = await adb.sync();
      const isDirectory = await sync.isDirectory(path);
      if (!isDirectory) {
        throw new Error("Selected path is not a directory");
      }

      const result = await adb.subprocess.noneProtocol.spawnWaitText(`ls ${path} -al`);
      const files = parseLsAlOutput(result);
      res.json({ result: files }).end();
    } catch (error: any) {
      Logger.error(`Error getting files: ${error}`);
      res.status(500).json({ error: "An error occurred while getting files." }).end();
    }
  };

  bugreportzStatus: RequestHandler = async (
    _req: Request,
    res: Response<BugreportzStatusResponse | IGenericErrRes>,
  ) => {
    try {
      const singleton = ManagerSingleton.getInstance();
      const adb = await singleton.getAdb();
      const tmpDir = singleton.getTmpDir();
      // 'bugreportz' creates /dev/socket/dumpstate when it's running
      const lsCmdResult = await adb.subprocess.noneProtocol?.spawnWaitText("ls /dev/socket/dumpstate");
      const isBugreportRunning = lsCmdResult.trim().includes("No such file or directory") ? false : true;
      const filePath = path.join(tmpDir, BUGREPORT_FILENAME);
      const bugreportFileExists = safeFileExists(filePath);

      res.json({ isRunning: isBugreportRunning, isBugreportAvailable: bugreportFileExists }).end();
    } catch (error: any) {
      Logger.error(`Error running bugreportz: ${error}`);
      res.status(500).json({ error: "An error occurred while running bugreportz." }).end();
    }
  };

  runBugreportz: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    let commandStarted = false;
    try {
      const singleton = ManagerSingleton.getInstance();
      const adb = await singleton.getAdb();
      const tmpDir = singleton.getTmpDir();
      // 'bugreportz' creates /dev/socket/dumpstate when it's running
      const lsCmdResult = await adb.subprocess.noneProtocol?.spawnWaitText("ls /dev/socket/dumpstate");
      const isBugreportRunning = lsCmdResult.trim().includes("No such file or directory") ? false : true;

      if (isBugreportRunning) {
        throw new Error("Bugreportz is already running");
      }

      res.json({ result: "bugreportz command started" }).end();
      commandStarted = true;

      const filePath = path.join(tmpDir, BUGREPORT_FILENAME);
      if (safeFileExists(filePath)) {
        await fs.unlink(filePath);
      }

      const bugreportData = await adb.subprocess.noneProtocol?.spawnWait("bugreportz -s");
      await fs.writeFile(filePath, bugreportData);
    } catch (error: any) {
      Logger.error(`Error running bugreportz: ${error}`);
      // If the command has started we mean the response was already returned to the client (let's just fail kinda silently)
      if (!commandStarted) {
        res.status(500).json({ error: "An error occurred while running bugreportz." }).end();
      }
    }
  };

  downloadBugreport: RequestHandler = async (req: Request, res: Response<Buffer<ArrayBufferLike> | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const tmpDir = ManagerSingleton.getInstance().getTmpDir();
      const filePath = path.join(tmpDir, BUGREPORT_FILENAME);
      if (!safeFileExists(filePath)) {
        res.status(400).json({ error: "Missing Bugreport file" }).end();
        return;
      }
      const bugreportContent = await fs.readFile(filePath);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=bugreport.zip");
      res.status(200).send(bugreportContent);
    } catch (error: any) {
      Logger.error(`Error downloading bugreport: ${error}`);
      res.status(500).json({ error: "An error occurred while downloading the bugreport." }).end();
    }
  };

  getPackageInfos: RequestHandler = async (req: Request, res: Response<CompanionPackageInfos[] | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const packagesRes = await adb.subprocess.noneProtocol.spawnWaitText("pm list packages -3");
      const packages = packagesRes.split("\n").map(el => el.split("package:")[1]);

      const client = CompanionClient.getInstance();
      const result: any = await client.sendMessage("getPackageInfos", { packageNames: packages });

      const packageInfos: CompanionPackageInfos[] = result.packageInfos
        .map(
          (el: any): CompanionPackageInfos => ({
            apkSize: el.apkSize ?? 0,
            icon: el.icon ?? "",
            label: el.label ?? "",
            packageName: el.packageName ?? "",
            versionName: el.versionName ?? "",
            firstInstallTime: el.firstInstallTime ?? 0,
            lastUpdateTime: el.lastUpdateTime ?? 0,
          }),
        )
        .sort((a: CompanionPackageInfos, b: CompanionPackageInfos) => a.label.localeCompare(b.label));

      res.json(packageInfos).end();
    } catch (error: any) {
      Logger.error(`Error getting packages info: ${error}`);
      res.status(500).json({ error: "An error occurred while getting packages info." }).end();
    }
  };

  apk: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      if (!req.file) {
        res.status(400).json({ error: "No file uploaded." }).end();
        return;
      }

      const adb = await ManagerSingleton.getInstance().getAdb();
      const sync = await adb.sync();
      const file = req.file as Express.Multer.File;
      const apkFilePath = file.path;
      const apkBuffer: Buffer = await fs.readFile(apkFilePath);
      const uploadedFilePath = path.resolve(DEFAULT_UPLOAD_FOLDER, file.filename);

      await sync.write({
        filename: uploadedFilePath,
        file: new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(apkBuffer));
            controller.close();
          },
        }),
      });

      const installRes = await adb.subprocess.noneProtocol.spawnWaitText(`pm install ${uploadedFilePath}`);
      await adb.rm(uploadedFilePath);
      await fs.unlink(apkFilePath); // Clean up the uploaded file

      if (installRes.trim() !== "Success") {
        res.status(500).json({ error: "An error occurred while installing the APK." }).end();
      } else {
        res.json({ result: "APK correctly installed." }).end();
      }
    } catch (error) {
      Logger.error(`Error importing database: ${error}`);
      res.status(500).json({ error: "An error occurred while installing the APK." }).end();
    }
  };

  getFridaLibrary: RequestHandler = async (req: Request, res: Response<FridaLibraryResponse | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const fridaLibrary = await loadFridaLibrary();
      res.json({ library: fridaLibrary }).end();
    } catch (error: any) {
      Logger.error(`Error getting Frida library: ${error}`);
      res.status(500).json({ error: "An error occurred while getting the Frida library." }).end();
    }
  };

  startExploitApp: RequestHandler = async (req: Request, res: Response<IGenericResultRes | IGenericErrRes>) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    let responseSent = false;
    try {
      const body = req.body as StartExploitAppRequest;
      const singleton = ManagerSingleton.getInstance();
      const config = singleton.getConfig();
      const duration = config.features.exploitAppDuration;

      const { packageName: exploitApp } = body;

      if (singleton.deviceApps.includes(exploitApp)) {
        throw new Error("This is not an exploit app!");
      }

      await singleton.runAppByPackageName(exploitApp);

      res.json({ result: `Exploit app correctly  for ${duration} seconds` }).end();
      responseSent = true;

      await sleep(duration * SECOND);
      Logger.info(`${duration} seconds have passed, restarting target app...`);
      await singleton.runTargetApp();
    } catch (error: any) {
      Logger.error(`Error starting exploit app: ${error}`);
      // Check if the response was already returned to the client (let's just fail kinda silently)
      if (!responseSent) {
        res.status(500).json({ error: "An error occurred while starting the exploit app." }).end();
      }
    }
  };

  genericError: RequestHandler = async (_req: Request, res: Response<IGenericResultRes>) => {
    res.status(400).json({ result: "This feature is either missing or disabled." }).end();
  };
}

export default new APIController();
