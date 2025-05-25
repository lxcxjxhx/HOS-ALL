import React, { useState, useEffect } from "react";
import to from "await-to-js";
import {
  ScrollView,
  Alert,
  StyleSheet,
  View,
  TouchableOpacity,
} from "react-native";
import {
  Input,
  Button,
  ButtonText,
  InputField,
  Text,
  AlertDialog,
  AlertDialogBackdrop,
  AlertDialogContent,
  AlertDialogHeader,
  Heading,
  AlertDialogBody,
  AlertDialogFooter,
  useToast,
  Toast,
  ToastTitle,
  ToastDescription,
  Spinner,
} from "@gluestack-ui/themed";

import MediaPicker from "@/components/MediaPicker";
import type { MediaAsset } from "@/components/MediaPicker";
import { useRouter, useNavigation, useLocalSearchParams } from "expo-router";
import { getFileMd5 } from "@/utils";
import { createTrip, preSignSingle, uploadFile } from "@/lib/api";
import { Trip } from "@/types";
import { useTrip } from "@/hooks/useTrips";
import { useUploadVideo } from "@/hooks/useUploadVideo";
import * as FileSystem from "expo-file-system";

export default function Publish() {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [images, setImages] = useState<MediaAsset[]>([]);
  const [video, setVideo] = useState<MediaAsset | null>(null);
  const [isDialogVisible, setDialogVisible] = useState(false);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const navigation = useNavigation();
  const toast = useToast();

  const params = useLocalSearchParams();
  const id = params.id as string | undefined;
  const { data: tripDetail } = useTrip(id || "");

  const isEdit = !!id;

  const [videoParams, setVideoParams] = useState<{
    uri: string;
    hash: string;
    size: number;
    filename: string;
  } | null>(null);

  useEffect(() => {
    if (id && tripDetail) {
      setTitle(tripDetail.title || "");
      setContent(tripDetail.content || "");
      setImages(
        (tripDetail.images || []).map((uri: string) => ({
          uri,
          type: "image",
        }))
      );
      if (tripDetail.video) {
        setVideo({
          uri: tripDetail.video,
          type: "video",
        });
      } else {
        setVideo(null);
      }
    }
  }, [id, tripDetail]);

  useEffect(() => {
    const unsubscribe = navigation.addListener("beforeRemove", (e) => {
      if (!title && !content && images.length === 0) {
        return;
      }
      e.preventDefault();
      setDialogVisible(true);
    });

    return unsubscribe;
  }, [navigation, title, content, images]);

  useEffect(() => {
    if (
      video &&
      video.uri &&
      video.fileSize &&
      video.fileSize > 50 * 1024 * 1024
    ) {
      getFileMd5(video.uri)
        .then((hash) => {
          console.log("hash", hash);
          setVideoParams({
            uri: video.uri,
            hash,
            size: video.fileSize || 0,
            filename: video.filename || "video.mp4",
          });
        })
        .catch((err) => {
          console.log(err);
        });
    } else {
      setVideoParams(null);
    }
  }, [video]);

  const { upload } = useUploadVideo(
    videoParams?.uri || "",
    videoParams?.hash || "",
    videoParams?.size || 0,
    videoParams?.filename || ""
  );

  const handleMediaChange = (assets: MediaAsset[]) => {
    setImages(assets.filter((a) => a.type === "image"));
    const videoAsset = assets.find((a) => a.type === "video");
    setVideo(videoAsset ? videoAsset : null);
  };

  const handleSubmit = async () => {
    if (!title || !content || images.length === 0) {
      Alert.alert("提示", "标题、内容、图片均为必填项");
      return;
    }
    setLoading(true);
    try {
      const requestBody: Trip = {
        title,
        content,
        _id: id,
      };
      let uploadedImages: string[] = [];
      for (let image of images) {
        if (image.uri.startsWith("file://")) {
          let filehash = await getFileMd5(image.uri);
          const [_, presignRes] = await to(
            preSignSingle(image.filename || "default.jpg", filehash)
          );
          if (presignRes && presignRes.code === 200) {
            if (presignRes.data.transferType === 1) {
              uploadedImages.push(presignRes.data.fileUrl);
            } else {
              if (image.uri) {
                const [__, uploadRes] = await to(uploadFile(image, filehash));
                if (uploadRes && uploadRes.code === 200) {
                  uploadedImages.push(uploadRes.data.url);
                } else {
                  Alert.alert(isEdit ? "修改失败" : "发布失败", "图片上传失败");
                  setLoading(false);
                  return;
                }
              } else {
                Alert.alert(isEdit ? "修改失败" : "发布失败", "图片上传失败");
                setLoading(false);
                return;
              }
            }
          } else {
            Alert.alert(isEdit ? "修改失败" : "发布失败", "图片上传失败");
            setLoading(false);
            return;
          }
        } else {
          uploadedImages.push(image.uri);
        }
      }
      requestBody.images = uploadedImages;
      if (video && video.uri) {
        if (video.uri.startsWith("file://")) {
          if (video.fileSize && video.fileSize > 50 * 1024 * 1024) {
            try {
              const url = await upload();
              requestBody.video = url;
            } catch (err) {
              console.log(err);
              Alert.alert(isEdit ? "修改失败" : "发布失败", "大视频上传失败");
              setLoading(false);
              return;
            }
          } else {
            let filehash = await getFileMd5(video.uri);
            const [_, presignRes] = await to(
              preSignSingle(video.filename || "video.mp4", filehash)
            );
            if (presignRes && presignRes.code === 200) {
              if (presignRes.data.transferType === 1) {
                requestBody.video = presignRes.data.fileUrl;
              } else {
                const [__, uploadRes] = await to(uploadFile(video, filehash));
                if (uploadRes?.code !== 200) {
                  Alert.alert(isEdit ? "修改失败" : "发布失败", "视频上传失败");
                  setLoading(false);
                  return;
                } else {
                  requestBody.video = uploadRes.data.url;
                }
              }
            } else {
              Alert.alert(isEdit ? "修改失败" : "发布失败", "视频上传失败");
              setLoading(false);
              return;
            }
          }
        } else {
          requestBody.video = video.uri;
        }
      }
      let result;
      if (isEdit) {
        const { updateTrip } = await import("@/lib/api");
        const [err, updateRes] = await to(updateTrip(requestBody));
        result = updateRes;
        if (err || !updateRes || updateRes.code !== 200) {
          Alert.alert("修改失败", "游记修改失败");
          setLoading(false);
          return;
        }
      } else {
        const [_, createRes] = await to(createTrip(requestBody));
        result = createRes;
        if (!createRes || createRes.code !== 200) {
          Alert.alert("发布失败", "游记发布失败");
          setLoading(false);
          return;
        }
      }
      router.push("/");
      toast.show({
        id: Math.random().toString(),
        placement: "top",
        duration: 3000,
        containerStyle: {
          position: "relative",
          top: 30,
        },
        render: ({ id }) => {
          const uniqueToastId = "toast-" + id;
          return (
            <Toast nativeID={uniqueToastId} action="success" variant="solid">
              <ToastDescription>
                {isEdit ? "游记修改成功" : "游记发布成功"}
              </ToastDescription>
            </Toast>
          );
        },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDialogClose = (confirm: boolean) => {
    setDialogVisible(false);
    if (confirm) {
      router.push("/");
    }
  };

  return (
    <View style={{ flex: 1, backgroundColor: "#fff" }}>
      {loading && (
        <View
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            width: "100%",
            height: "100%",
            zIndex: 9999,
            backgroundColor: "rgba(255,255,255,0.5)",
            justifyContent: "center",
            alignItems: "center",
          }}
        >
          <Spinner size="large" color="#3ec6fd" />
        </View>
      )}
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <MediaPicker
          onChange={handleMediaChange}
          value={[...images, ...(video ? [video] : [])]}
        />
        <Input style={[styles.input, { marginBottom: 0 }]} variant="underlined">
          <InputField
            placeholder="请输入标题（必填）"
            value={title}
            onChangeText={setTitle}
            style={styles.inputField}
            maxLength={50}
            multiline={false}
          />
        </Input>
        <View style={styles.divider} />
        <Input
          style={[styles.input, { minHeight: 300, borderBottomWidth: 0 }]}
          variant="underlined"
        >
          <InputField
            placeholder="请输入内容（必填）"
            value={content}
            onChangeText={setContent}
            style={[styles.inputField, styles.textarea]}
            multiline={true}
            numberOfLines={15}
          />
        </Input>
      </ScrollView>
      <View style={styles.footer}>
        <Button
          onPress={handleSubmit}
          style={{ borderRadius: 24, height: 48, backgroundColor: "#3ec6fd" }}
        >
          <ButtonText style={{ fontSize: 18, color: "#fff" }}>
            {isEdit ? "修改游记" : "发布游记"}
          </ButtonText>
        </Button>
      </View>
      <AlertDialog
        isOpen={isDialogVisible}
        onClose={() => handleDialogClose(false)}
      >
        <AlertDialogBackdrop />
        <AlertDialogContent>
          <AlertDialogHeader>
            <Heading className="text-typography-950 font-semibold" size="md">
              您还没有提交，确定要退出发布吗？
            </Heading>
          </AlertDialogHeader>
          <AlertDialogBody className="mt-3 mb-4">
            <Text size="sm">未发布的内容将不会被保存，您是否选择继续退出</Text>
          </AlertDialogBody>
          <AlertDialogFooter className="">
            <Button
              variant="outline"
              action="secondary"
              onPress={() => handleDialogClose(false)}
              size="sm"
              className="mr-2"
            >
              <ButtonText>取消</ButtonText>
            </Button>
            <Button size="sm" onPress={() => handleDialogClose(true)}>
              <ButtonText>确定</ButtonText>
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </View>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: "row",
    alignItems: "center",
    height: 56,
    paddingHorizontal: 8,
    borderBottomWidth: 1,
    borderBottomColor: "#f0f0f0",
    backgroundColor: "#fff",
  },
  backBtn: {
    padding: 4,
    marginRight: 8,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: "bold",
    color: "#222",
  },
  input: {
    borderWidth: 0,
    borderBottomWidth: 0,
    backgroundColor: "transparent",
    marginBottom: 16,
    paddingHorizontal: 0,
    paddingVertical: 0,
    elevation: 0,
    shadowOpacity: 0,
  },
  inputField: {
    borderWidth: 0,
    backgroundColor: "transparent",
    fontSize: 16,
    paddingHorizontal: 0,
    paddingVertical: 0,
    minHeight: 36,
  },
  textarea: {
    textAlignVertical: "top",
    flex: 1,
  },
  footer: {
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    padding: 16,
    backgroundColor: "#fff",
    borderTopWidth: 1,
    borderTopColor: "#f0f0f0",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: -2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 5,
  },
  divider: {
    height: 1,
    backgroundColor: "#e0e0e0",
    marginVertical: 8,
  },
});
