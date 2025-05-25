import { useCallback } from "react";
import { preSignChunk, uploadChunk, reportChunk, mergeChunks } from "@/lib/api";
import { uint8ArrayToFormFile } from "@/utils";
import * as FileSystem from "expo-file-system";

const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB
const BATCH_SIZE = 3; // 每组3个chunk
const RETRY_TIMES = 3; // 重试次数

// 边读边传单个分片
async function readChunk(
  uri: string,
  chunkIndex: number,
  chunkSize: number
): Promise<Uint8Array> {
  console.log("readChunk", chunkIndex);
  const start = chunkIndex * chunkSize;
  const base64Data = await FileSystem.readAsStringAsync(uri, {
    encoding: FileSystem.EncodingType.Base64,
    position: start,
    length: chunkSize,
  });
  const binary = atob(base64Data);
  const buffer = new Uint8Array(binary.length);
  for (let j = 0; j < binary.length; j++) {
    buffer[j] = binary.charCodeAt(j);
  }
  return buffer;
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function uploadChunkWithRetry(
  videoUri: string,
  chunk_idx: number,
  CHUNK_SIZE: number,
  fileHash: string
) {
  let lastError;
  for (let attempt = 1; attempt <= RETRY_TIMES; attempt++) {
    try {
      const chunk = await readChunk(videoUri, chunk_idx, CHUNK_SIZE);
      console.log(`chunk-${chunk_idx}`, chunk.byteLength, `try ${attempt}`);
      const formFile = await uint8ArrayToFormFile(chunk, `chunk-${chunk_idx}`);
      await uploadChunk(formFile.uri, fileHash, chunk_idx);
      await reportChunk(fileHash, chunk_idx);
      return;
    } catch (err) {
      lastError = err;
      console.warn(`chunk-${chunk_idx} 第${attempt}次上传失败`, err);
      if (attempt < RETRY_TIMES) await sleep(500 * attempt); // 递增延时
    }
  }
  throw lastError;
}

/**
 * useUploadVideo
 * @param videoUri 本地视频uri
 * @param fileHash 文件hash
 * @param fileSize 文件大小（字节）
 * @returns upload: () => Promise<string>  返回最终文件url
 */
export function useUploadVideo(
  videoUri: string,
  fileHash: string,
  fileSize: number,
  filename: string
) {
  const upload = useCallback(async () => {
    // 1. 预签名
    const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);
    const presignRes = await preSignChunk(
      fileHash,
      totalChunks,
      filename || "video.mp4"
    );
    if (presignRes.code !== 200) throw new Error("预签名失败");
    if (presignRes.data.transferType === 1) {
      // 秒传
      return presignRes.data.fileUrl;
    }
    // 2. batch分组上传
    if (!presignRes.data.needUploadChunks) {
      throw new Error("后端未返回传输节点");
    }
    const failedChunks: number[] = [];
    for (
      let batchStart = 0;
      batchStart < presignRes.data.needUploadChunks.length;
      batchStart += BATCH_SIZE
    ) {
      const batch = [];
      for (
        let i = 0;
        i < BATCH_SIZE &&
        batchStart + i < presignRes.data.needUploadChunks.length;
        i++
      ) {
        const idx = batchStart + i;
        batch.push(
          (async () => {
            if (
              presignRes.data.needUploadChunks &&
              presignRes.data.needUploadChunks[idx] !== undefined
            ) {
              let chunk_idx = presignRes.data.needUploadChunks[idx];
              try {
                await uploadChunkWithRetry(
                  videoUri,
                  chunk_idx,
                  CHUNK_SIZE,
                  fileHash
                );
              } catch (err) {
                // 记录失败分片
                failedChunks.push(chunk_idx);
                console.warn(`chunk-${chunk_idx} 最终上传失败`, err);
              }
            } else {
              // 记录无效分片
              failedChunks.push(-1);
            }
          })()
        );
      }
      await Promise.all(batch); // 等待本组全部上传完再进入下一组
    }
    // 3. 检查失败分片
    if (failedChunks.length > 0) {
      throw new Error(`以下分片上传失败: ${failedChunks.join(",")}`);
    }
    // 4. 合并分片
    const mergeRes = await mergeChunks(fileHash, filename || "video.mp4");
    if (mergeRes.code !== 200) throw new Error("合并分片失败");
    return mergeRes.data;
  }, [videoUri, fileHash, fileSize, filename]);

  return { upload };
}
