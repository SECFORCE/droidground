import { http } from '@client/api/axios';
import { DeviceInfoResponse, DroidGroundFeaturesResponse, IGenericResultRes } from '@shared/api';
import { AxiosResponse } from 'axios';

// This functions are just used to wrap specific REST API calls
// Not using try/catch statement here so every specific component
// can handle the error in his own way
class RESTManager {
  async getFeatures(): Promise<AxiosResponse<DroidGroundFeaturesResponse>> {
    const res = await http.get<DroidGroundFeaturesResponse>("/features");
    return res;
  }

  async getInfo(): Promise<AxiosResponse<DeviceInfoResponse>> {
    const res = await http.get<DeviceInfoResponse>("/info");
    return res;
  }

  async dumpLogcat(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>("/logcat");
    return res;
  }

  async clearLogcat(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.delete<IGenericResultRes>("/logcat");
    return res;
  }

  async shutdown(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>("/shutdown");
    return res;
  }

  async reboot(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>("/reboot");
    return res;
  }
}
export const RESTManagerInstance = new RESTManager();