import AsyncStorage from "@react-native-async-storage/async-storage";

// 存储 token
export const storeToken = async (token: string): Promise<void> => {
  try {
    await AsyncStorage.setItem("userToken", token);
  } catch (error) {
    console.error("Error storing token", error);
  }
};

// 获取 token
export const getToken = async (): Promise<string | null> => {
  try {
    const token = await AsyncStorage.getItem("userToken");
    return token;
  } catch (error) {
    console.error("Error retrieving token", error);
    return null;
  }
};
