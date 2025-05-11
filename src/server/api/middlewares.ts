import { Request, Response, NextFunction } from "express";

export const checkFeatureEnabled = (isFeatureEnabled: boolean) =>{
    return  (_req: Request, res: Response, next: NextFunction) => {
        isFeatureEnabled ? next() : res.status(400).json({ 'message': 'This feature is either missing or disabled.'}).end();
      }
}