import { Server as HTTPServer } from "http";
import express from "express";
import { Application as ExpressApplication } from "express";
import cors from "cors";
import { ManagerSingleton } from "@server/manager";
import api from "@server/api";
import { setupWs } from "@server/ws";
import Logger from "@shared/logger";
import { resourceFile, safeFileExists } from "@server/utils/helpers";
import { RESOURCES } from "@server/config";
import { setupFrida } from "@server/utils/frida";
import { setupScrcpy } from "@server/utils/scrcpy";

const checkResources = () => {
  Logger.debug("Check resources...");
  const companionFile = resourceFile(RESOURCES.COMPANION_FILE);
  const scrcpyFile = resourceFile(RESOURCES.SCRCPY_SERVER);
  if (!safeFileExists(companionFile)) {
    Logger.error(`Companion file is missing, run 'npm run companion' to generate it`);
    process.exit(1);
  }
  if (!safeFileExists(scrcpyFile)) {
    Logger.error(`Scrcpy server is missing, run 'npm run scrcpy' to generate it`);
    process.exit(1);
  }
  Logger.debug("Check resources done!");
};

const setupApi = async (app: ExpressApplication) => {
  app.use(
    cors({
      exposedHeaders: ["Content-Disposition"],
    }),
  );
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Load routes
  app.use("/api/v1", api());
};

export const serverApp = async (app: ExpressApplication, httpServer: HTTPServer) => {
  checkResources();
  const manager = ManagerSingleton.getInstance();

  await manager.init(httpServer);
  // A device is needed, otherwise there's nothing to do here

  await manager.setAdb();
  await manager.setCtf();

  if (manager.getConfig().features.fridaEnabled) {
    await setupFrida();
  }

  await manager.runTargetApp(); // Start the target app
  await setupApi(app);
  await setupWs(httpServer);
  await setupScrcpy();
};
