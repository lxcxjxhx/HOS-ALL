import { Trip } from "@/types";
import request from "@/utils/request";
import { storeToken } from "@/utils/token";
import { PresignedType, UploadFileResponse } from "./type";
import { MediaAsset } from "@/components/MediaPicker";

const mockTrips: Trip[] = Array.from({ length: 20 }, (_, i) => ({
  _id: `${i + 1}`,
  id: `${i + 1}`,
  title: `Trip ${i + 1}`,
  content: `This is the content for trip ${i + 1}.`,
  images: [
    `https://picsum.photos/200/300?random=${i}`,
    `https://picsum.photos/200/300?random=${i + 1}`,
    `https://picsum.photos/200/300?random=${i + 2}`,
  ],
  createdAt: new Date().toISOString(),
}));

// console.log(JSON.stringify(mockTrips));

export const fetchTrips = async (
  page: number,
  limit: number,
  query: string = "",
  authorId?: string,
  status?: string
) => {
  // console.log(page, limit, query, authorId, status);
  try {
    const response = await request.get("/diary/pagelist", {
      params: {
        page,
        limit,
        title: query,
        authorId,
        status,
      },
    });
    console.log(response.data);
    return {
      trips: response.data,
      total: response.data.length,
    };
  } catch (error) {
    console.error("Error fetching trips:", error);
    throw error;
  }
};

export const fetchTripById = async (id: string): Promise<Trip> => {
  // console.log(id);
  const res = await request.get<any, UploadFileResponse<Trip>>(
    "/diary/detail",
    {
      params: {
        _id: id,
      },
    }
  );
  return res.data;
};

export const createTrip = async (
  trip: Trip
): Promise<UploadFileResponse<any>> => {
  // await new Promise((resolve) => setTimeout(resolve, 500));
  const res = await request.post<any, any>("/diary/publish", trip);
  return res;
};

export const updateTrip = async (
  trip: Trip
): Promise<UploadFileResponse<Trip>> => {
  const res = await request.put<any, UploadFileResponse<Trip>>(
    "/diary/update",
    trip
  );
  return res;
};

export const deleteTrip = async (
  id: string
): Promise<UploadFileResponse<any>> => {
  const res = await request.delete<any, UploadFileResponse<any>>(
    "/diary/delete",
    { data: { _id: id } }
  );
  return res;
};

export const login = async (
  username: string,
  password: string
): Promise<boolean> => {
  try {
    const response = await request.post<
      any,
      {
        code: number;
        data: { token: string };
        msg: string;
      }
    >("/users/login", {
      username,
      password,
    });
    // console.log(response);
    // return false;
    if (response.code === 200) {
      const token = response.data.token;
      await storeToken(token);
      return true;
    }
    return false;
  } catch (error) {
    console.error("Error logging in:", error);
    return false;
  }
};

export const uploadFile = async (
  file: MediaAsset,
  filehash: string
): Promise<UploadFileResponse<{ url: string }>> => {
  const formData = new FormData();
  formData.append("file", {
    uri: file.uri,
    name:
      file.filename || (file.type === "video" ? "default.mp4" : "default.jpg"),
    type: file.type === "video" ? "video/mp4" : "image/jpeg",
  } as any);
  formData.append("fileHash", filehash);
  const response = await request.post<any, UploadFileResponse<{ url: string }>>(
    "/upload/upload-single",
    formData,
    {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    }
  );
  return response;
};

export const preSignSingle = async (
  filename: string,
  filehash: string
): Promise<UploadFileResponse<PresignedType>> => {
  const response = await request.post<any, UploadFileResponse<PresignedType>>(
    "/upload/pre-sign-single",
    {
      filename,
      fileHash: filehash,
    }
  );
  return response;
};

export const preSignChunk = async (
  fileHash: string,
  totalChunks: number,
  filename: string
): Promise<UploadFileResponse<PresignedType>> => {
  const response = await request.post<any, UploadFileResponse<PresignedType>>(
    "/upload/pre-sign",
    {
      fileHash,
      totalChunks,
      filename,
    }
  );
  return response;
};

export const uploadChunk = async (
  chunkUri: string,
  fileHash: string,
  chunkIndex: number
): Promise<UploadFileResponse<any>> => {
  console.log("uploadChunk", chunkIndex);
  const formData = new FormData();
  formData.append("file", {
    uri: chunkUri,
    name: `chunk-${chunkIndex}`,
    type: "application/octet-stream",
  } as any);
  formData.append("fileHash", fileHash);
  formData.append("chunkIndex", chunkIndex.toString());
  // console.log("formData", formData);
  // console.log("uploadChunk", formData.get("file"));
  const response = await request.post<any, UploadFileResponse<any>>(
    "/upload/upload-chunk",
    formData,
    {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    }
  );
  console.log("uploadChunk response", response, chunkIndex);
  return response;
};

export const reportChunk = async (
  fileHash: string,
  chunkIndex: number
): Promise<UploadFileResponse<any>> => {
  const response = await request.post<any, UploadFileResponse<any>>(
    "/upload/report-chunk",
    {
      fileHash,
      chunkIndex,
    }
  );
  return response;
};

export const mergeChunks = async (
  fileHash: string,
  filename: string
): Promise<UploadFileResponse<string>> => {
  const response = await request.post<any, UploadFileResponse<string>>(
    "/upload/merge-report",
    {
      fileHash,
      filename,
    }
  );
  return response;
};
