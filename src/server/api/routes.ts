// Package imports
import path from "path";
import { Router } from "express";
import multer from "multer";

// Local imports
import APIController from "@server/api/controller";
import { ManagerSingleton } from "@server/manager";
import { checkFeatureEnabled } from "@server/api/middlewares";
import { REST_API_ENDPOINTS as E } from "@shared/endpoints";

const singleton = ManagerSingleton.getInstance();
const upload = multer({ dest: path.join(singleton.getTmpDir(), "uploads") });
const endpoint = Router(); // Define an Express Router
const features = singleton.getConfig().features;

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

  endpoint.get(E.FEATURES, APIController.features);
  endpoint.get(E.INFO, APIController.info);
  endpoint.post(E.ACTIVITY, checkFeatureEnabled(features.startActivityEnabled), APIController.startActivity);
  endpoint.post(E.BROADCAST, checkFeatureEnabled(features.startBroadcastReceiverEnabled), APIController.startBroadcast);
  endpoint.post(E.SERVICE, checkFeatureEnabled(features.startServiceEnabled), APIController.startService);
  endpoint.post(E.SHUTDOWN, checkFeatureEnabled(features.shutdownEnabled), APIController.shutdown);
  endpoint.post(E.REBOOT, checkFeatureEnabled(features.rebootEnabled), APIController.reboot);
  endpoint.post(E.LOGCAT, checkFeatureEnabled(features.logcatEnabled), APIController.dumpLogcat);
  endpoint.delete(E.LOGCAT, checkFeatureEnabled(features.logcatEnabled), APIController.clearLogcat);
  endpoint.post(E.FILES, checkFeatureEnabled(features.fileBrowserEnabled), APIController.files);
  endpoint.get(E.BUGREPORT_STATUS, checkFeatureEnabled(features.bugReportEnabled), APIController.bugreportzStatus);
  endpoint.post(E.BUGREPORT, checkFeatureEnabled(features.bugReportEnabled), APIController.runBugreportz);
  endpoint.get(E.BUGREPORT, checkFeatureEnabled(features.bugReportEnabled), APIController.downloadBugreport);
  endpoint.get(E.PACKAGES, checkFeatureEnabled(features.appManagerEnabled), APIController.getPackageInfos);
  endpoint.post(E.APK, checkFeatureEnabled(features.appManagerEnabled), upload.single("apkFile"), APIController.apk);

  endpoint.all("/*all", APIController.genericError);
};
