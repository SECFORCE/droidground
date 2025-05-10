// Package imports
import { Router } from 'express';

// Local imports
import APIController from '@server/api/controller';

const endpoint = Router(); // Define an Express Router

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

  endpoint.post('/activity', APIController.startActivity)
  endpoint.post('/frida', APIController.runFridaScript)
  endpoint.post('/logcat', APIController.dumpLogcat)
  endpoint.delete('/logcat', APIController.clearLogcat)
};