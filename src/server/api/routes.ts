// Package imports
import { Router } from 'express';

// Local imports
import APIController from '@server/api/controller';
import { ManagerSingleton } from '@server/manager';
import { checkFeatureEnabled } from './middlewares';

const endpoint = Router(); // Define an Express Router
const features = ManagerSingleton.getInstance().getConfig().features;

// Endpoint implementation
export default (app: Router) => {
  app.use('', endpoint);

  // Cache-control middleware for all routes within this router
  endpoint.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
  });

  endpoint.get('/features', APIController.features)
  endpoint.get('/info', APIController.info)
  endpoint.post('/activity', checkFeatureEnabled(features.startActivityEnabled),  APIController.startActivity)
  endpoint.post('/shutdown', checkFeatureEnabled(features.shutdownEnabled), APIController.shutdown)
  endpoint.post('/reboot', checkFeatureEnabled(features.rebootEnabled), APIController.reboot)
  endpoint.post('/logcat', checkFeatureEnabled(features.logcatEnabled), APIController.dumpLogcat)
  endpoint.delete('/logcat', checkFeatureEnabled(features.logcatEnabled), APIController.clearLogcat)
  endpoint.post('/files', checkFeatureEnabled(features.fileBrowserEnabled), APIController.files)
  endpoint.get('/bugreport', checkFeatureEnabled(features.bugReportEnabled), APIController.bugreportzStatus)
  endpoint.post('/bugreport', checkFeatureEnabled(features.bugReportEnabled), APIController.runBugreportz)
  endpoint.all('/*all', APIController.genericError)
};