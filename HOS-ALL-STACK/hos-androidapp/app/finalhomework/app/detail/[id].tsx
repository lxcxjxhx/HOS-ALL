import React, { useState } from "react";
import { Box, HStack, Text } from "@gluestack-ui/themed";
import { useTrip } from "@/hooks/useTrips";
import { useLocalSearchParams } from "expo-router";
import {
  Dimensions,
  View,
  Image as RNImage,
  Modal,
  TouchableOpacity,
  StyleSheet,
  ScrollView as RNScrollView,
  ActivityIndicator,
} from "react-native";
import { Video, ResizeMode } from "expo-av";
import { Skeleton, SkeletonText } from "@/components/ui/skeleton";

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get("window");

function formatDate(dateStr?: string) {
  if (!dateStr) return "";
  const date = new Date(dateStr);
  const pad = (n: number) => (n < 10 ? "0" + n : n);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export default function Detail() {
  const { id } = useLocalSearchParams();
  const { data, isLoading, error } = useTrip(id as string);
  const [previewIndex, setPreviewIndex] = useState<number | null>(null);
  const [isVideoFullscreen, setIsVideoFullscreen] = useState(false);

  if (isLoading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color="#0000ff" />
      </View>
    );
  }

  if (error || !data) return <Text>Error loading trip</Text>;

  const renderMedia = (media: string, index: number) => {
    return (
      <TouchableOpacity
        key={`${media}-${index}`}
        activeOpacity={0.9}
        onPress={() => {
          setPreviewIndex(index);
          setIsVideoFullscreen(false);
        }}
      >
        <RNImage
          source={{ uri: media }}
          style={{
            width: SCREEN_WIDTH,
            height: SCREEN_HEIGHT * 0.5,
            resizeMode: "cover",
          }}
        />
      </TouchableOpacity>
    );
  };

  // 合并视频和图片数组
  const allMedia = data.video
    ? [
        { type: "video", uri: data.video },
        ...(data.images || []).map((uri) => ({ type: "image", uri })),
      ]
    : (data.images || []).map((uri) => ({ type: "image", uri }));

  return (
    <View style={{ flex: 1, backgroundColor: "#fff" }}>
      <RNScrollView
        style={{ flex: 1 }}
        contentContainerStyle={{ paddingBottom: 80 }}
      >
        {/* 媒体轮播区域 */}
        <RNScrollView
          horizontal
          pagingEnabled
          showsHorizontalScrollIndicator={false}
          style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT * 0.5 }}
        >
          {allMedia.map((media, idx) =>
            media.type === "video" ? (
              <TouchableOpacity
                key={`video-${idx}`}
                activeOpacity={0.9}
                onPress={() => {
                  setPreviewIndex(idx);
                  setIsVideoFullscreen(true);
                }}
              >
                <Video
                  source={{ uri: media.uri }}
                  style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT * 0.5 }}
                  resizeMode={ResizeMode.COVER}
                  useNativeControls={false}
                  shouldPlay={false}
                />
                <View style={styles.playButton}>
                  <Text style={styles.playButtonText}>▶</Text>
                </View>
              </TouchableOpacity>
            ) : (
              <TouchableOpacity
                key={`image-${idx}`}
                activeOpacity={0.9}
                onPress={() => {
                  setPreviewIndex(idx);
                  setIsVideoFullscreen(false);
                }}
              >
                <RNImage
                  source={{ uri: media.uri }}
                  style={{
                    width: SCREEN_WIDTH,
                    height: SCREEN_HEIGHT * 0.5,
                    resizeMode: "cover",
                  }}
                />
              </TouchableOpacity>
            )
          )}
        </RNScrollView>
        {/* 内容区域 */}
        <View style={{ padding: 20 }}>
          <Text style={{ fontSize: 24, fontWeight: "bold", marginBottom: 12 }}>
            {data.title}
          </Text>
          <Text style={{ color: "#888", marginBottom: 16 }}>
            {formatDate(data.createdAt)}
          </Text>
          <Text style={{ fontSize: 16, color: "#222" }}>{data.content}</Text>
        </View>
      </RNScrollView>
      {/* 全屏预览 */}
      <Modal
        visible={previewIndex !== null}
        transparent
        animationType="fade"
        onRequestClose={() => {
          setPreviewIndex(null);
          setIsVideoFullscreen(false);
        }}
      >
        <View style={styles.modalBg}>
          {isVideoFullscreen ? (
            <TouchableOpacity
              activeOpacity={1}
              onPress={() => {
                setPreviewIndex(null);
                setIsVideoFullscreen(false);
              }}
              style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT }}
            >
              <Video
                source={{ uri: data.video || "" }}
                style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT }}
                useNativeControls
                resizeMode={ResizeMode.CONTAIN}
                shouldPlay
                isLooping
              />
              <TouchableOpacity
                style={styles.closeButton}
                onPress={() => {
                  setPreviewIndex(null);
                  setIsVideoFullscreen(false);
                }}
              >
                <Text style={styles.closeButtonText}>×</Text>
              </TouchableOpacity>
            </TouchableOpacity>
          ) : (
            <RNScrollView
              horizontal
              pagingEnabled
              showsHorizontalScrollIndicator={false}
              contentOffset={{ x: (previewIndex ?? 0) * SCREEN_WIDTH, y: 0 }}
              style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT }}
            >
              {allMedia.map((media, idx) => (
                <TouchableOpacity
                  key={`${media.type}-${idx}`}
                  style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT }}
                  activeOpacity={1}
                  onPress={() => {
                    setPreviewIndex(null);
                    setIsVideoFullscreen(false);
                  }}
                >
                  {media.type === "video" ? (
                    <Video
                      source={{ uri: media.uri }}
                      style={{ width: SCREEN_WIDTH, height: SCREEN_HEIGHT }}
                      useNativeControls
                      resizeMode={ResizeMode.CONTAIN}
                      shouldPlay
                      isLooping
                    />
                  ) : (
                    <RNImage
                      source={{ uri: media.uri }}
                      style={{
                        width: SCREEN_WIDTH,
                        height: SCREEN_HEIGHT,
                        resizeMode: "contain",
                        backgroundColor: "#000",
                      }}
                    />
                  )}
                </TouchableOpacity>
              ))}
            </RNScrollView>
          )}
        </View>
      </Modal>
      {/* 页脚 */}
      <View style={styles.footer}>
        <Text style={{ color: "#888", fontSize: 14 }}>© 2025 旅行日记</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  centered: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  modalBg: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.95)",
    justifyContent: "center",
    alignItems: "center",
  },
  footer: {
    position: "absolute",
    left: 0,
    right: 0,
    bottom: 0,
    height: 56,
    backgroundColor: "#fff",
    borderTopWidth: 1,
    borderTopColor: "#eee",
    justifyContent: "center",
    alignItems: "center",
    zIndex: 10,
  },
  playButton: {
    position: "absolute",
    top: "50%",
    left: "50%",
    transform: [{ translateX: -25 }, { translateY: -25 }],
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: "rgba(0, 0, 0, 0.5)",
    justifyContent: "center",
    alignItems: "center",
  },
  playButtonText: {
    color: "#fff",
    fontSize: 24,
  },
  closeButton: {
    position: "absolute",
    top: 10,
    right: 10,
    width: 30,
    height: 30,
    borderRadius: 15,
    backgroundColor: "rgba(0, 0, 0, 0.5)",
    justifyContent: "center",
    alignItems: "center",
  },
  closeButtonText: {
    color: "#fff",
    fontSize: 20,
  },
});
