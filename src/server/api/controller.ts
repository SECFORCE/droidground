// Node.js imports
import path from "path";
import fs from "fs/promises";

// Package imports
import { RequestHandler } from "express";
import { ReadableStream } from "@yume-chan/stream-extra";

// Local imports
import Logger from "@server/utils/logger";
import { ManagerSingleton } from "@server/manager";
import {
  CompanionPackageInfos,
  DeviceInfoResponse,
  GetFilesRequest,
  StartActivityRequest,
  StartBroadcastRequest,
  StartServiceRequest,
} from "@shared/api";
import {
  buildExtra,
  parseLsAlOutput,
  safeFileExists,
  shellEscape,
  versionNumberToCodename,
} from "@server/utils/helpers";
import { capitalize } from "@shared/helpers";
import { CompanionClient } from "@server/companion";
import { BUGREPORT_FILENAME, DEFAULT_UPLOAD_FOLDER } from "@server/config";
import { CompanionAttackSurfaceResponse } from "@server/utils/types";

class APIController {
  features: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const droidGroundConfig = ManagerSingleton.getInstance().getConfig();
      res.json({ features: droidGroundConfig.features }).end();
    } catch (error: any) {
      Logger.error("Error getting features config:", error);
      res.status(500).json({ message: "An error occurred while getting features config." }).end();
    }
  };

  info: RequestHandler = async (req, res) => {
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
      Logger.error("Error getting info:", error);
      res.status(500).json({ message: "An error occurred while getting device info." }).end();
    }
  };

  startActivity: RequestHandler = async (req, res) => {
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
        res.status(400).json({ message: "This activity is not exported by the target app" }).end();
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
      parts.push(shellEscape(`${config.packageName}/${body.activity}`));

      const command = parts.join(" ");
      Logger.debug(`Running command: "${command}"`);
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(command);
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error starting activity:", error);
      res.status(500).json({ message: "An error occurred while starting the activity." }).end();
    }
  };

  startBroadcast: RequestHandler = async (req, res) => {
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
        res.status(400).json({ message: "This receiver is not exported by the target app" }).end();
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
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error starting broadcast:", error);
      res.status(500).json({ message: "An error occurred while starting the broadcast." }).end();
    }
  };

  startService: RequestHandler = async (req, res) => {
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
        res.status(400).json({ message: "This service is not exported by the target app" }).end();
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
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error starting service:", error);
      res.status(500).json({ message: "An error occurred while starting the service." }).end();
    }
  };

  shutdown: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot -p`);
      res.json({ result: "Device shutted down" }).end();
    } catch (error: any) {
      Logger.error("Error shutting down the device:", error);
      res.status(500).json({ message: "An error occurred while shutting down the device." }).end();
    }
  };

  reboot: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot`);
      res.json({ result: "Device rebooted" }).end();
    } catch (error: any) {
      Logger.error("Error rebooting the device:", error);
      res.status(500).json({ message: "An error occurred while rebooting the device." }).end();
    }
  };

  dumpLogcat: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(`logcat -d -t 500`);
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error dumping logcat:", error);
      res.status(500).json({ message: "An error occurred while dumping logcat." }).end();
    }
  };

  clearLogcat: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawn(`logcat -c`);
      res.json({ result: "Logcat cleared" }).end();
    } catch (error: any) {
      Logger.error("Error clearing logcat:", error);
      res.status(500).json({ message: "An error occurred while clearing logcat." }).end();
    }
  };

  files: RequestHandler = async (req, res) => {
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
      Logger.error("Error getting files:", error);
      res.status(500).json({ message: "An error occurred while getting files." }).end();
    }
  };

  bugreportzStatus: RequestHandler = async (req, res) => {
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
      Logger.error("Error running bugreportz:", error);
      res.status(500).json({ message: "An error occurred while running bugreportz." }).end();
    }
  };

  runBugreportz: RequestHandler = async (req, res) => {
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
      Logger.error("Error running bugreportz:", error);
      // If the command has started we mean the response was already returned to the client (let's just fail kinda silently)
      if (!commandStarted) {
        res.status(500).json({ message: "An error occurred while running bugreportz." }).end();
      }
    }
  };

  downloadBugreport: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      const tmpDir = ManagerSingleton.getInstance().getTmpDir();
      const filePath = path.join(tmpDir, BUGREPORT_FILENAME);
      if (!safeFileExists(filePath)) {
        res.status(400).json({ message: "Missing Bugreport file" }).end();
        return;
      }
      const bugreportContent = await fs.readFile(filePath);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=bugreport.zip");
      res.status(200).send(bugreportContent);
    } catch (error: any) {
      Logger.error("Error downloading bugreport:", error);
      res.status(500).json({ message: "An error occurred while downloading the bugreport." }).end();
    }
  };

  getPackageInfos: RequestHandler = async (req, res) => {
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
      Logger.error("Error getting packages info:", error);
      res.status(500).json({ message: "An error occurred while getting packages info." }).end();
    }
  };

  apk: RequestHandler = async (req, res) => {
    Logger.info(`Received ${req.method} request on ${req.path}`);
    try {
      if (!req.file) {
        res.status(400).json({ message: "No file uploaded." }).end();
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
        res.status(500).json({ message: "An error occurred while installing the APK." }).end();
      } else {
        res.json({ result: "APK correctly installed." }).end();
      }
    } catch (error) {
      Logger.error("Error importing database:", error);
      res.status(500).json({ message: "An error occurred while installing the APK." }).end();
    }
  };

  genericError: RequestHandler = async (_req, res) => {
    res.status(400).json({ message: "This feature is either missing or disabled." }).end();
  };
}

export default new APIController();
