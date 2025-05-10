import axios, { AxiosInstance } from 'axios';
import { BACKEND } from '@client/config';

const instance: AxiosInstance = axios.create({ baseURL: BACKEND.BASE_URL });
  
export const http = instance;
