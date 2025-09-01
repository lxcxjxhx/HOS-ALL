import React from "react";
import {
  Box,
  Image,
  Text,
  Pressable,
  Card,
  HStack,
  VStack,
  AvatarFallbackText,
  Avatar,
  AvatarImage,
} from "@gluestack-ui/themed";
import { useRouter } from "expo-router";
import { Dimensions } from "react-native";
import { Trip } from "@/types";
import { useTheme } from "../app/(tabs)/settings"; // 尝试保留相对路径
// 备选：使用绝对路径（需配置 tsconfig.json）
// import { useTheme } from "@/app/(tabs)/settings";
import colors from "tailwindcss/colors";

const { width: WINDOW_WIDTH } = Dimensions.get("window");

function formatDate(dateStr?: string) {
  if (!dateStr) return "";
  const date = new Date(dateStr);
  const pad = (n: number) => (n < 10 ? "0" + n : n);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export const TripCard: React.FC<{ trip: Trip }> = ({ trip }) => {
  const router = useRouter();
  const { theme } = useTheme();

  const cardWidth = Math.min(WINDOW_WIDTH * 0.46, 320);
  const imageWidth = cardWidth - 20 - 5;

  return (
    <Pressable onPress={() => router.push(`/detail/${trip._id}`)}>
      <Card
        className="rounded-lg max-w-[360px] m-0 mb-3"
        style={{
          padding: 0,
          marginLeft: 5,
          marginRight: 5,
          // width: cardWidth,
          backgroundColor: theme === "light" ? colors.white : "#333",
        }}
      >
        <Box style={{ height: 90 }}>
          <Image
            source={{ uri: trip.images?.[0] || "" }}
            alt="trip image"
            className="mb-6 w-full rounded-t-lg"
            style={{ width: "100%" }}
          />
        </Box>
        <Box className="p-2 pt-0 mt-0">
          <Text
            className="mb-2"
            numberOfLines={2}
            style={{
              color: theme === "light" ? colors.gray[900] : colors.white,
              // minHeight: 45,
            }}
          >
            {trip.title || "（未命名行程）"}
          </Text>
          <HStack space="sm">
            <Box>
              <Avatar size="sm">
                <AvatarFallbackText>JD</AvatarFallbackText>
                <AvatarImage
                  source={{
                    uri: "https://gluestack.github.io/public-blog-video-assets/camera.png",
                  }}
                  alt="avatar"
                />
              </Avatar>
            </Box>
            <VStack>
              <Text
                style={{
                  fontSize: 13,
                  color: theme === "light" ? colors.gray[900] : colors.white,
                }}
              >
                {trip.username}
              </Text>
              <Text
                style={{
                  fontSize: 10,
                  color:
                    theme === "light" ? colors.gray[700] : colors.gray[200],
                }}
                className="flex-1"
              >
                {formatDate(trip.createdAt)}
              </Text>
            </VStack>
          </HStack>
        </Box>
      </Card>
    </Pressable>
  );
};
