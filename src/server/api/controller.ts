// Package imports
import { RequestHandler } from 'express';
import frida from "frida";

// Local imports
import Logger from '@server/utils/logger';
import { ManagerSingleton } from '@server/manager';
import { RunFridaScriptRequest, StartActivityRequest } from '@shared/api';


interface FridaState {
    device: frida.Device | null;
    pid: frida.ProcessID | null;
    script: frida.Script | null;
}

const current: FridaState = {
    device: null,
    pid: null,
    script: null
};


function onOutput(pid: frida.ProcessID, fd: frida.FileDescriptor, data: Buffer) {
    if (pid !== current.pid)
        return;

    let description: string;
    if (data.length > 0) {
        description = "\"" + data.toString().replace(/\n/g, "\\n") + "\"";
    } else {
        description = "<EOF>";
    }
    console.log(`[*] onOutput(pid=${pid}, fd=${fd}, data=${description})`);
}

function onMessage(message: frida.Message, data: Buffer | null) {
    console.log("[*] onMessage() message:", message, "data:", data);
}

function onDetached(reason: frida.SessionDetachReason) {
    console.log(`[*] onDetached(reason="${reason}")`);
    current.device!.output.disconnect(onOutput);
}

class APIController {
    startActivity: RequestHandler = async (req, res, _next) => {
        try {
            const body = req.body as StartActivityRequest;
            const activity = body.activity;
            const adb = await ManagerSingleton.getInstance().getAdb();
          
            const result = await adb.subprocess.noneProtocol.spawnWaitText(`am start -n ${activity}`)
            res.json({ result: result  }).end();
        } catch (error: any) {
            Logger.error('Error starting activity:', error);
            res.status(500).json({ message: 'An error occurred while starting the activity.' }).end();
        }
    }

    shutdown: RequestHandler = async (_req, res, _next) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            const result = await adb.subprocess.noneProtocol.spawnWaitText(`reboot -p`)
            res.json({ result: result  }).end();
        } catch (error: any) {
            Logger.error('Error shutting down the device:', error);
            res.status(500).json({ message: 'An error occurred while shutting down the device.' }).end();
        }
    }

    reboot: RequestHandler = async (_req, res, _next) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            const result = await adb.subprocess.noneProtocol.spawnWaitText(`reboot`)
            res.json({ result: result  }).end();
        } catch (error: any) {
            Logger.error('Error rebooting the device:', error);
            res.status(500).json({ message: 'An error occurred while rebooting the device.' }).end();
        }
    }

    dumpLogcat: RequestHandler = async (_req, res, _next) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            const result = await adb.subprocess.noneProtocol.spawnWaitText(`logcat -d -t 500`)
            res.json({ result: result  }).end();
        } catch (error: any) {
            Logger.error('Error dumping logcat:', error);
            res.status(500).json({ message: 'An error occurred while dumping logcat.' }).end();
        }
    }


    clearLogcat: RequestHandler = async (_req, res, _next) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            const result = await adb.subprocess.noneProtocol.spawnWaitText(`logcat -c`)
            res.json({ result: result  }).end();
        } catch (error: any) {
            Logger.error('Error clearing logcat:', error);
            res.status(500).json({ message: 'An error occurred while clearing logcat.' }).end();
        }
    }


    runFridaScript: RequestHandler = async (req, res, _next) => {
        try {
            const body = req.body as RunFridaScriptRequest;
            const scriptContent = body.script;
            const device = await frida.getUsbDevice();
            current.device = device;
            device.output.connect(onOutput);

            const pid = await device.spawn(process.env.DROIDGROUND_APP_PACKAGE_NAME as string)

            const session = await device.attach(pid);
            session.detached.connect(onDetached);

            console.log(`[*] createScript()`);
            const script = await session.createScript(scriptContent);
            current.script = script;
            script.message.connect(onMessage);
            await script.load();
        
            console.log(`[*] resume(${pid})`);
            await device.resume(pid);

            res.status(200).json({ message: 'Frida script started' }).end();
        } catch (error: any) {
            Logger.error('Error starting Frida script:', error);
            res.status(500).json({ message: 'An error occurred while starting the Frida script.' }).end();
        }
    }
}

export default new APIController();