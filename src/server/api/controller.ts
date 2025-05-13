// Package imports
import { RequestHandler } from 'express';

// Local imports
import Logger from '@server/utils/logger';
import { ManagerSingleton } from '@server/manager';
import { DeviceInfoResponse, StartActivityRequest } from '@shared/api';
import { versionNumberToCodename } from '@server/utils/helpers';
import { capitalize } from '@shared/helpers';

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

    genericError: RequestHandler = async (_req, res) => {
        res.status(400).json({ message: 'This feature is either missing or disabled.'}).end()
    }
}

export default new APIController();