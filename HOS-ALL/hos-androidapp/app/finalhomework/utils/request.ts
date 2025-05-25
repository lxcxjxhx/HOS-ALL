import axios, {
  AxiosRequestConfig,
  AxiosResponse,
  AxiosError,
  InternalAxiosRequestConfig,
} from "axios";
import { getToken } from "./token";
import config from "@/config";

// 创建 axios 实例
const instance = axios.create({
  baseURL: config.api.baseURL, // 使用配置文件中的 baseURL
  timeout: 10000,
});

// 请求拦截器
instance.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    const token = await getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: AxiosError) => {
    return Promise.reject(error);
  }
);

// 响应拦截器
instance.interceptors.response.use(
  (response: AxiosResponse) => {
    return response.data;
  },
  (error: AxiosError) => {
    if (error.response && error.response.status !== 200) {
      console.error("Error:", error.response.status, error.response.data);
    }
    return Promise.reject(error);
  }
);

export default instance;
