import express from 'express';
import routes from '@server/api/routes';

export default (): express.Router => {
  const app: express.Router = express.Router();
  routes(app);
  return app;
};