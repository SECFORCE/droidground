// Package imports
import { RequestHandler, Request, Response } from "express";

// Local imports
import { IGenericResultRes } from "@shared/api";

class APIController {
  genericError: RequestHandler = async (_req: Request, res: Response<IGenericResultRes>) => {
    res.status(400).json({ result: "This feature is either missing or disabled." }).end();
  };
}

export default new APIController();
