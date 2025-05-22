// Package imports
import path from "path";
import { Router } from "express";
import multer from "multer";

// Local imports
import APIController from "@server/api/controller";
import { ManagerSingleton } from "@server/manager";
import { checkFeatureEnabled, validateBody } from "@server/api/middlewares";
import { getFilesSchema, startActivitySchema, startBroadcastSchema, startServiceSchema } from "@server/api/schemas";
import { REST_API_ENDPOINTS as E } from "@shared/endpoints";
import { GetFilesRequest, StartActivityRequest, StartBroadcastRequest, StartServiceRequest } from "@shared/api";

const singleton = ManagerSingleton.getInstance();
const upload = multer({ dest: path.join(singleton.getTmpDir(), "uploads") });
const endpoint = Router(); // Define an Express Router
const features = singleton.getConfig().features;
const fridaJailEnabled = features.fridaType === "full" ? false : true;

// Endpoint implementation
export default (app: Router) => {
  app.use("", endpoint);

  // Cache-control middleware for all routes within this router
  endpoint.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
  });

  endpoint.post(
    E.ACTIVITY,
    checkFeatureEnabled(features.startActivityEnabled),
    validateBody<StartActivityRequest>(startActivitySchema),
    APIController.startActivity,
  );
  endpoint.post(
    E.BROADCAST,
    checkFeatureEnabled(features.startBroadcastReceiverEnabled),
    validateBody<StartBroadcastRequest>(startBroadcastSchema),
    APIController.startBroadcast,
  );
  endpoint.post(
    E.SERVICE,
    checkFeatureEnabled(features.startServiceEnabled),
    validateBody<StartServiceRequest>(startServiceSchema),
    APIController.startService,
  );
  endpoint.post(
    E.FILES,
    checkFeatureEnabled(features.fileBrowserEnabled),
    validateBody<GetFilesRequest>(getFilesSchema),
    APIController.files,
  );
  endpoint.post(E.RESET, APIController.reset);
  endpoint.get(E.FEATURES, APIController.features);
  endpoint.get(E.INFO, APIController.info);
  endpoint.post(E.RESTART, APIController.restartApp);
  endpoint.post(E.SHUTDOWN, checkFeatureEnabled(features.shutdownEnabled), APIController.shutdown);
  endpoint.post(E.REBOOT, checkFeatureEnabled(features.rebootEnabled), APIController.reboot);
  endpoint.post(E.LOGCAT, checkFeatureEnabled(features.logcatEnabled), APIController.dumpLogcat);
  endpoint.delete(E.LOGCAT, checkFeatureEnabled(features.logcatEnabled), APIController.clearLogcat);
  endpoint.get(E.BUGREPORT_STATUS, checkFeatureEnabled(features.bugReportEnabled), APIController.bugreportzStatus);
  endpoint.post(E.BUGREPORT, checkFeatureEnabled(features.bugReportEnabled), APIController.runBugreportz);
  endpoint.get(E.BUGREPORT, checkFeatureEnabled(features.bugReportEnabled), APIController.downloadBugreport);
  endpoint.get(E.PACKAGES, checkFeatureEnabled(features.appManagerEnabled), APIController.getPackageInfos);
  endpoint.post(E.APK, checkFeatureEnabled(features.appManagerEnabled), upload.single("apkFile"), APIController.apk);
  endpoint.get(E.LIBRARY, checkFeatureEnabled(fridaJailEnabled), APIController.getFridaLibrary);

  endpoint.all("/*all", APIController.genericError);
};
