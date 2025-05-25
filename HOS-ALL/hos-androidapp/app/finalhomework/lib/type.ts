export type UploadFileResponse<T> = {
  code: number;
  data: T;
  msg: string;
};

export type PresignedType = {
  transferType: number;
  uploadedChunks?: number[] | null;
  needUploadChunks?: number[] | null;
  fileUrl: string;
};
