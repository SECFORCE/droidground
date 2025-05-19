import { http } from "@client/api/axios";
import {
  BugreportzStatusResponse,
  CompanionPackageInfos,
  DeviceInfoResponse,
  DroidGroundFeaturesResponse,
  GetFilesRequest,
  GetFilesResponse,
  IGenericResultRes,
  StartActivityRequest,
} from "@shared/api";
import { AxiosResponse } from "axios";

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

  async startActivity(data: StartActivityRequest): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>("/activity", data);
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

  async getFiles(data: GetFilesRequest): Promise<AxiosResponse<GetFilesResponse>> {
    const res = await http.post<GetFilesResponse>("/files", data);
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

  async startBugreportz(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>("/bugreport");
    return res;
  }

  async getBugreportzStatus(): Promise<AxiosResponse<BugreportzStatusResponse>> {
    const res = await http.get<BugreportzStatusResponse>("/bugreport");
    return res;
  }

  async downloadBugreport(): Promise<AxiosResponse<any>> {
    const res = await http.get<any>("/bugreport/download", { responseType: "blob" });
    return res;
  }

  async getPackageInfos(): Promise<AxiosResponse<CompanionPackageInfos[]>> {
    const res = await http.get<CompanionPackageInfos[]>("packages");
    return res;
  }
}
export const RESTManagerInstance = new RESTManager();
