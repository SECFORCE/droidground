import { Adb, AdbServerClient, AdbTransport } from "@yume-chan/adb";
import { AdbServerNodeTcpConnector } from "@yume-chan/adb-server-node-tcp";

import Logger from '@server/utils/logger';
import { sleep } from "@shared/helpers";

export class ManagerSingleton {
    private static instance: ManagerSingleton;
    private serverClient: AdbServerClient | null = null;
    private adb: Adb | null = null;
  
    private constructor() {
      // private constructor prevents direct instantiation
    }
  
    public static getInstance(): ManagerSingleton {
      if (!ManagerSingleton.instance) {
        ManagerSingleton.instance = new ManagerSingleton();
      }
      return ManagerSingleton.instance;
    }

    public async init() {
        const connector: AdbServerNodeTcpConnector = new AdbServerNodeTcpConnector({
            host: "localhost",
            port: 5037,
          });
      
        const client: AdbServerClient = new AdbServerClient(connector);
        this.serverClient = client;
        const observer = await client.trackDevices();

        observer.onDeviceAdd((devices) => {
            for (const device of devices) {
                console.log("add")
              console.log(device.serial);
            }
        });
          
        observer.onDeviceRemove((devices) => {
            for (const device of devices) {
                console.log("remove")
              console.log(device.serial);
            }
        })
    }

    private async setupAdb(): Promise<Adb> {
        const serverClient = this.serverClient as AdbServerClient;
      
        const devices: AdbServerClient.Device[] = await serverClient.getDevices();
        if (devices.length === 0) {
          Logger.error("No device connected");
          throw new Error("No device connected");
        }
      
        Logger.debug("Listing devices (and using the first one)")
        Logger.debug(devices)
        const device = devices[0];
          
        const transport: AdbTransport = await serverClient.createTransport(device);
        const adb: Adb = new Adb(transport);
        return adb;
    }

    public async setAdb() {
        let adb: Adb;
        while (true) {
            try {
                adb = await this.setupAdb();
                this.adb = adb;
                break;
            } catch (e) {
                Logger.error(`Error while trying to setup adb connection: ${e}`);
                Logger.error("Waiting for 5 seconds before retry...")
                await sleep(5000);
            }
        }
    }
  
    public async getAdb(): Promise<Adb> {
        if (!this.adb) {
            await this.setAdb();
        }
        return this.adb as Adb; // We can cast
    }
}