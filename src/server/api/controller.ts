// Node.js imports
import path from "path";
import fs from "fs/promises";
// Package imports
import { RequestHandler } from "express";

// Local imports
import Logger from "@server/utils/logger";
import { ManagerSingleton } from "@server/manager";
import { CompanionPackageInfos, DeviceInfoResponse, GetFilesRequest, StartActivityRequest } from "@shared/api";
import { parseLsAlOutput, safeFileExists, versionNumberToCodename } from "@server/utils/helpers";
import { capitalize } from "@shared/helpers";
import { CompanionClient } from "@server/companion";

class APIController {
  features: RequestHandler = async (_req, res) => {
    try {
      const droidGroundConfig = ManagerSingleton.getInstance().getConfig();
      res.json({ features: droidGroundConfig.features }).end();
    } catch (error: any) {
      Logger.error("Error getting features config:", error);
      res.status(500).json({ message: "An error occurred while getting features config." }).end();
    }
  };

  info: RequestHandler = async (_req, res) => {
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
    try {
      const body = req.body as StartActivityRequest;
      const activity = body.activity;
      const adb = await ManagerSingleton.getInstance().getAdb();

      const result = await adb.subprocess.noneProtocol.spawnWaitText(`am start -n ${activity}`);
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error starting activity:", error);
      res.status(500).json({ message: "An error occurred while starting the activity." }).end();
    }
  };

  shutdown: RequestHandler = async (_req, res) => {
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot -p`);
      res.json({ result: "Device shutted down" }).end();
    } catch (error: any) {
      Logger.error("Error shutting down the device:", error);
      res.status(500).json({ message: "An error occurred while shutting down the device." }).end();
    }
  };

  reboot: RequestHandler = async (_req, res) => {
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      await adb.subprocess.noneProtocol.spawnWait(`reboot`);
      res.json({ result: "Device rebooted" }).end();
    } catch (error: any) {
      Logger.error("Error rebooting the device:", error);
      res.status(500).json({ message: "An error occurred while rebooting the device." }).end();
    }
  };

  dumpLogcat: RequestHandler = async (_req, res) => {
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      const result = await adb.subprocess.noneProtocol.spawnWaitText(`logcat -d -t 500`);
      res.json({ result: result }).end();
    } catch (error: any) {
      Logger.error("Error dumping logcat:", error);
      res.status(500).json({ message: "An error occurred while dumping logcat." }).end();
    }
  };

  clearLogcat: RequestHandler = async (_req, res) => {
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

  bugreportzStatus: RequestHandler = async (_req, res) => {
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      // 'bugreportz' creates /dev/socket/dumpstate when it's running
      const lsCmdResult = await adb.subprocess.noneProtocol?.spawnWaitText("ls /dev/socket/dumpstate");
      const isBugreportRunning = lsCmdResult.trim().includes("No such file or directory") ? false : true;
      const filePath = path.join("/tmp", `bugreportz.zip`); // TODO: Save in a specific folder
      const bugreportFileExists = safeFileExists(filePath);

      res.json({ isRunning: isBugreportRunning, isBugreportAvailable: bugreportFileExists }).end();
    } catch (error: any) {
      Logger.error("Error running bugreportz:", error);
      res.status(500).json({ message: "An error occurred while running bugreportz." }).end();
    }
  };

  runBugreportz: RequestHandler = async (_req, res) => {
    let commandStarted = false;
    try {
      const adb = await ManagerSingleton.getInstance().getAdb();
      // 'bugreportz' creates /dev/socket/dumpstate when it's running
      const lsCmdResult = await adb.subprocess.noneProtocol?.spawnWaitText("ls /dev/socket/dumpstate");
      const isBugreportRunning = lsCmdResult.trim().includes("No such file or directory") ? false : true;

      if (isBugreportRunning) {
        throw new Error("Bugreportz is already running");
      }

      res.json({ result: "bugreportz command started" }).end();
      commandStarted = true;

      const filePath = path.join("/tmp", `bugreportz.zip`); // TODO: Save in a specific folder
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

  downloadBugreport: RequestHandler = async (_req, res) => {
    try {
      const filePath = path.join("/tmp", `bugreportz.zip`); // TODO: Save in a specific folder
      if (!safeFileExists(filePath)) {
        res.status(400).json({ message: "Missing Bugreport file" }).end();
      }
      const bugreportContent = await fs.readFile(filePath);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=bugreport.zip");
      res.status(200).send(bugreportContent);
    } catch (error: any) {
      Logger.error("Error downloading bugreport:", error);
      res.status(500).json({ message: "An error occurred while donwloading the bugreport." }).end();
    }
  };

  getPackageInfos: RequestHandler = async (_req, res) => {
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
    } catch (e) {}
  };

  genericError: RequestHandler = async (_req, res) => {
    res.status(400).json({ message: "This feature is either missing or disabled." }).end();
  };
}

export default new APIController();
