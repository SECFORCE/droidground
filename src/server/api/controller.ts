// Package imports
import { RequestHandler } from 'express';
import frida from "frida";

// Local imports
import Logger from '@server/utils/logger';
import { ManagerSingleton } from '@server/manager';
import { DeviceInfoResponse, RunFridaScriptRequest, StartActivityRequest } from '@shared/api';
import { versionNumberToCodename } from '@server/utils/helpers';
import { capitalize } from '@shared/helpers';
import { sendStructuredMessage } from '@server/utils/ws';
import { WSMessageType } from '@shared/types';
import { appendFileSync, readFileSync, writeFileSync } from 'fs';


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

const fridaOutputFile = '/tmp/frida.out'

const onOutput = (pid: frida.ProcessID, fd: frida.FileDescriptor, data: Buffer) => {
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

const onDetached = (reason: frida.SessionDetachReason) => {
    console.log(`[*] onDetached(reason="${reason}")`);
    current.device!.output.disconnect(onOutput);
}

const onMessage = (m: frida.Message, data: Buffer | null) => {
    const message = m as frida.SendMessage;
    Logger.info("Frida message:", message, "data:", data);
    const websocketClients = ManagerSingleton.getInstance().wsStreamingClients; // Change this to specific wss
    for (const [_wsClientId, client] of websocketClients) {
        sendStructuredMessage(client.ws, WSMessageType.FRIDA_OUTPUT, {});
    }
    appendFileSync(fridaOutputFile, `${message.payload}\n`)
}

class APIController {
    features: RequestHandler = async (_req, res) => {
        try {
            const droidGroundConfig = ManagerSingleton.getInstance().getConfig()
            res.json({ features: droidGroundConfig.features }).end();
        } catch (error: any) {
            Logger.error('Error getting features config:', error);
            res.status(500).json({ message: 'An error occurred while getting features config.' }).end();
        }
    }

    info: RequestHandler = async (_req, res) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            const versionResult = await adb.subprocess.noneProtocol.spawnWaitText('getprop ro.build.version.release');
            const processorResult = await adb.subprocess.noneProtocol.spawnWaitText('getprop ro.product.cpu.abi');
            const deviceTypeResult = await adb.subprocess.noneProtocol.spawnWaitText('getprop ro.kernel.qemu');
            const modelResult = await adb.subprocess.noneProtocol.spawnWaitText('getprop ro.product.model');
            const manufacturerResult = await adb.subprocess.noneProtocol.spawnWaitText('getprop ro.product.manufacturer');

            const codename = versionNumberToCodename(versionResult.trim());

            const response: DeviceInfoResponse = {
                version: `${versionResult.trim()} (${codename})`,
                deviceType: deviceTypeResult.trim() === '1' ? 'Emulator' : 'Device',
                architecture: processorResult.trim(),
                model: `${capitalize(manufacturerResult.trim())} ${modelResult.trim()}`
            }
            res.json(response).end();
        } catch (error: any) {
            Logger.error('Error getting info:', error);
            res.status(500).json({ message: 'An error occurred while getting device info.' }).end();
        }
    }

    startActivity: RequestHandler = async (req, res) => {
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

    shutdown: RequestHandler = async (_req, res) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            await adb.subprocess.noneProtocol.spawnWait(`reboot -p`)
            res.json({ result: "Device shutted down"  }).end();
        } catch (error: any) {
            Logger.error('Error shutting down the device:', error);
            res.status(500).json({ message: 'An error occurred while shutting down the device.' }).end();
        }
    }

    reboot: RequestHandler = async (_req, res) => {
        try {
            const adb = await ManagerSingleton.getInstance().getAdb();
            await adb.subprocess.noneProtocol.spawnWait(`reboot`)
            res.json({ result: "Device rebooted"  }).end();
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
            await adb.subprocess.noneProtocol.spawn(`logcat -c`)
            res.json({ result: "Logcat cleared"  }).end();
        } catch (error: any) {
            Logger.error('Error clearing logcat:', error);
            res.status(500).json({ message: 'An error occurred while clearing logcat.' }).end();
        }
    }

    runFridaScript: RequestHandler = async (req, res, _next) => {
        try {
            const body = req.body as RunFridaScriptRequest;
            const scriptContent = body.script;
            writeFileSync(fridaOutputFile, "");
            const device = await frida.getUsbDevice();
            current.device = device;
            device.output.connect(onOutput);

            const droidGroundConfig = ManagerSingleton.getInstance().getConfig()

            const pid = await device.spawn(droidGroundConfig.packageName)

            const session = await device.attach(pid);
            session.detached.connect(onDetached);

            console.log(`[*] createScript()`);

            console.log(scriptContent);

            const script = await session.createScript(scriptContent);
            current.script = script;
            script.message.connect(onMessage);
            await script.load();
        
            console.log(`[*] resume(${pid})`);
            await device.resume(pid);

            res.status(200).json({ result: 'Frida script started' }).end();
        } catch (error: any) {
            Logger.error('Error starting Frida script:', error);
            res.status(500).json({ message: 'An error occurred while starting the Frida script.' }).end();
        }
    }

    getFridaOutput: RequestHandler = async (req, res, _next) => {
        try {
            const fridaOutput = readFileSync(fridaOutputFile, 'utf-8');
            res.status(200).json({ output: fridaOutput }).end();
        } catch (error: any) {
            Logger.error('Error getting Frida output:', error);
            res.status(500).json({ message: 'An error occurred while getting Frida output.' }).end();
        }
    }

    genericError: RequestHandler = async (_req, res) => {
        res.status(400).json({ message: 'This feature is either missing or disabled.'}).end()
    }
}

export default new APIController();