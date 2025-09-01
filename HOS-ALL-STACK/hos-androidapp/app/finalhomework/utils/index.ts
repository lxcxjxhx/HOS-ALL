// import crypto from "crypto";
import * as FileSystem from "expo-file-system";
import { Platform } from "react-native";
import { Alert } from "react-native";

export const getFileMd5 = async (filepath: string): Promise<string> => {
  //   console.log("filepath", filepath);
  const info = await FileSystem.getInfoAsync(filepath, { md5: true });
  if (!info.exists) {
    // throw new Error("文件不存在: " + filepath);
    Alert.alert("文件不存在", filepath);
    return Promise.reject("文件不存在");
  }
  if (!info.md5) {
    Alert.alert("文件md5获取失败", filepath);
    return Promise.reject("文件md5获取失败");
  }
  return info.md5;
};

/**
 * 将 Uint8Array 转存为临时文件，并构造成可上传的文件对象
 * @param chunk Uint8Array 二进制数据
 * @param filename 文件名（例如 chunk_0.mp4）
 * @returns FormData 可用的 { uri, name, type }
 */
export async function uint8ArrayToFormFile(
  chunk: Uint8Array,
  filename: string
): Promise<{ uri: string; name: string; type: string }> {
  // 分批转换，避免爆栈
  function uint8ArrayToString(u8arr: Uint8Array) {
    const CHUNK_SIZE = 0x8000; // 32KB
    let result = "";
    for (let i = 0; i < u8arr.length; i += CHUNK_SIZE) {
      result += String.fromCharCode.apply(null, [
        ...u8arr.subarray(i, i + CHUNK_SIZE),
      ]);
    }
    return result;
  }
  const str = uint8ArrayToString(chunk);
  const base64 = btoa(str);

  const fileUri = `${FileSystem.cacheDirectory}${filename}`;
  await FileSystem.writeAsStringAsync(fileUri, base64, {
    encoding: FileSystem.EncodingType.Base64,
  });
  console.log("uint8ArrayToFormFile", filename, fileUri);
  return {
    uri: Platform.OS === "android" ? fileUri : fileUri.replace("file://", ""),
    name: filename,
    type: "application/octet-stream", // 可根据需要设置为 video/mp4 等
  };
}

/**
 * 将 file:// 本地文件按块大小分片
 * @param uri 本地文件路径（file://...）
 * @param chunkSize 每片大小（字节）
 * @returns Promise<Array<{ file: Uint8Array, chunkIndex: number }>>
 */
export async function sliceFileToChunks(
  uri: string,
  chunkSize: number
): Promise<{ file: Uint8Array; chunkIndex: number }[]> {
  const chunks: { file: Uint8Array; chunkIndex: number }[] = [];

  const fileInfo = await FileSystem.getInfoAsync(uri);
  if (!fileInfo.exists || !fileInfo.size) {
    throw new Error("文件不存在或无法读取大小");
  }

  const totalSize = fileInfo.size;
  const totalChunks = Math.ceil(totalSize / chunkSize);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const length = Math.min(chunkSize, totalSize - start);

    const base64Data = await FileSystem.readAsStringAsync(uri, {
      encoding: FileSystem.EncodingType.Base64,
      position: start,
      length,
    });

    const binary = atob(base64Data);
    const buffer = new Uint8Array(binary.length);
    for (let j = 0; j < binary.length; j++) {
      buffer[j] = binary.charCodeAt(j);
    }

    chunks.push({ file: buffer, chunkIndex: i });
  }

  return chunks;
}
