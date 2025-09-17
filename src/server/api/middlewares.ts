import { Request, Response, NextFunction } from "express";
import Ajv, { JSONSchemaType } from "ajv";

// Middleware to check if the feature is enabled
export const checkFeatureEnabled = (isFeatureEnabled: boolean) => {
  return (_req: Request, res: Response, next: NextFunction) => {
    isFeatureEnabled ? next() : res.status(400).json({ message: "This feature is either missing or disabled." }).end();
  };
};

// Validation middleware
const ajv = new Ajv();

export const validateBody = <T>(schema: JSONSchemaType<T>) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.body) {
      res.status(400).json({ message: "The body cannot be empty." }).end();
      return;
    }

    const isValid = ajv.validate(schema, req.body);

    isValid ? next() : res.status(400).json({ message: "Invalid body" }).end();
  };
};

export const checkDebugToken = (token: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization ?? "";

    authHeader.trim() === token
      ? next()
      : res.status(400).json({ message: "This feature is either missing or disabled." }).end();
  };
};
