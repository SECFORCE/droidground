import { http } from '@client/api/axios';
import { AxiosResponse } from 'axios';

// This functions are just used to wrap specific REST API calls
// Not using try/catch statement here so every specific component
// can handle the error in his own way
class RESTManager {
  async dumpLogcat(): Promise<AxiosResponse<any>> {
    const res = await http.post<any>("/logcat");
    return res;
  }

  async clearLogcat(): Promise<AxiosResponse<any>> {
    const res = await http.delete<any>("/logcat");
    return res;
  }
}
export const RESTManagerInstance = new RESTManager();