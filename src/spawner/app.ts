import express from "express";
import { Application as ExpressApplication } from "express";
import api from "@spawner/api";

const setupApi = async (app: ExpressApplication) => {
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Load routes
  app.use("/api/v1", api());
};

export const spawnerApp = async (app: ExpressApplication) => {
  await setupApi(app);
};
