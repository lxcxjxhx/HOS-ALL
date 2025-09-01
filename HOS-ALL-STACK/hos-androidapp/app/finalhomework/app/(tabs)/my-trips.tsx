import React, { useEffect, useState } from "react";
import { FlatList, StyleSheet, Alert } from "react-native";
import {
  Box,
  Text,
  Button,
  ButtonText,
  Spinner,
  Card,
  HStack,
  VStack,
  Image,
} from "@gluestack-ui/themed";
import { useMyTrips, useCreateTrip, useUpdateTrip } from "@/hooks/useTrips";
import { TripCard } from "@/components/TripCard";
import { TripForm } from "@/components/TripForm";
import { Trip } from "@/types";
import colors from "tailwindcss/colors";
import { useTheme } from "./settings"; // 导入 useTheme
import { useNavigation, useRouter } from "expo-router";
import { deleteTrip as apiDeleteTrip } from "@/lib/api";

const MyTripsCard = ({
  trip,
  onDelete,
}: {
  trip: Trip;
  onDelete: (id: string) => void;
}) => {
  const { theme } = useTheme(); // 获取当前主题
  const router = useRouter(); // 新增

  // 动态样式
  const styles = StyleSheet.create({
    title: {
      color: theme === "light" ? colors.gray[900] : colors.white, // 标题文字颜色
      fontSize: 16,
      fontWeight: "bold",
      width: 170,
      textOverflow: "ellipsis",
    },
    content: {
      color: theme === "light" ? colors.gray[600] : colors.gray[300], // 内容文字颜色
      fontSize: 13,
    },
    buttonSolid: {
      backgroundColor:
        trip.status === "approved"
          ? theme === "light"
            ? "green"
            : colors.green[600]
          : trip.status === "pedding"
          ? theme === "light"
            ? colors.yellow[500]
            : colors.yellow[600]
          : theme === "light"
          ? colors.red[500]
          : colors.red[600],
    },
    buttonOutline: {
      borderColor: theme === "light" ? colors.gray[300] : colors.gray[600], // 边框颜色
    },
    buttonText: {
      color: theme === "light" ? colors.gray[900] : colors.white, // 按钮文字颜色
    },
  });

  const getStatusText = () => {
    switch (trip.status) {
      case "approved":
        return "已通过";
      case "pedding":
        return "待审核";
      case "rejected":
        return "未通过";
      default:
        return "未知状态";
    }
  };

  const handleEdit = () => {
    router.push({ pathname: "/publish", params: { id: trip._id } });
  };

  const handleDelete = () => {
    Alert.alert("确认删除", "确定要删除该游记吗？删除后不可恢复。", [
      { text: "取消", style: "cancel" },
      {
        text: "删除",
        style: "destructive",
        onPress: () => {
          if (trip._id) onDelete(trip._id);
        },
      },
    ]);
  };

  return (
    <Card
      className="flex-row m-4 p-4 rounded-lg shadow-md mb-1"
      style={{
        padding: 0,
        backgroundColor: theme === "light" ? colors.white : "#333", // 动态卡片背景
      }}
    >
      <VStack className="flex-1 ml-3 mt-3 mb-3 pr-2" space="xl">
        <HStack space="md">
          <Image
            source={{ uri: trip.images?.[0] }}
            alt="trip image"
            className="w-32 aspect-[3/2]"
            style={{ width: 120 }}
          />
          <VStack space="sm">
            <Text
              className="font-bold text-lg"
              style={styles.title}
              numberOfLines={1}
            >
              {trip.title}
            </Text>
            <Box>
              <Text
                className="text-gray-600"
                numberOfLines={2}
                style={[styles.content, { width: 170 }]}
              >
                {trip.content}
              </Text>
            </Box>
          </VStack>
        </HStack>
        <HStack space="sm" className="flex">
          <Button variant="solid" style={styles.buttonSolid} size="sm">
            <ButtonText style={[styles.buttonText, { color: "white" }]}>
              {getStatusText()}
            </ButtonText>
          </Button>
          <HStack space="sm" className="justify-self-end ml-auto">
            <Button
              variant="outline"
              style={styles.buttonOutline}
              size="sm"
              onPress={handleDelete}
            >
              <ButtonText style={styles.buttonText}>删除</ButtonText>
            </Button>
            <Button
              variant="outline"
              style={styles.buttonOutline}
              size="sm"
              onPress={handleEdit}
            >
              <ButtonText style={styles.buttonText}>编辑</ButtonText>
            </Button>
          </HStack>
        </HStack>
      </VStack>
    </Card>
  );
};

export default function MyTrips() {
  const { theme } = useTheme(); // 获取当前主题
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, refetch } =
    useMyTrips("", undefined, undefined);
  const { mutate: createTrip } = useCreateTrip();
  const { mutate: updateTrip } = useUpdateTrip();
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingTrip, setEditingTrip] = useState<Trip | null>(null);
  const [refreshFlag, setRefreshFlag] = useState(0);

  const trips = data?.pages.flatMap((page) => page.trips) || []; // 修复语法错误
  const navigation = useNavigation();

  // const handleSubmit = (values: Omit<Trip, "id" | "createdAt">) => {
  //   if (editingTrip) {
  //     updateTrip({ id: editingTrip.id, trip: values });
  //   } else {
  //     createTrip(values);
  //   }
  //   setIsFormOpen(false);
  //   setEditingTrip(null);
  // };

  useEffect(() => {
    const unsubscribe = navigation.addListener("focus", () => {
      // Fetch or refresh data here
    });
    return unsubscribe;
  }, [navigation]);

  // 删除后刷新
  const handleDelete = async (id: string) => {
    try {
      await apiDeleteTrip(id);
      setRefreshFlag((f) => f + 1); // 触发刷新
    } catch (e) {
      Alert.alert("删除失败", "游记删除失败，请重试");
    }
  };

  useEffect(() => {
    if (refreshFlag > 0) {
      refetch();
    }
  }, [refreshFlag, refetch]);

  return (
    <Box
      className="flex-1 p-4"
      style={{
        padding: 0,
        backgroundColor: theme === "light" ? colors.white : "#333", // 动态背景
      }}
    >
      <FlatList
        data={trips}
        renderItem={({ item }) => (
          <Box className="flex-row justify-between items-center" key={item._id}>
            <MyTripsCard trip={item} key={item._id} onDelete={handleDelete} />
          </Box>
        )}
        keyExtractor={(item) => item._id}
        numColumns={1}
        onEndReached={() =>
          hasNextPage && !isFetchingNextPage && fetchNextPage()
        }
        onEndReachedThreshold={0.5}
        ListFooterComponent={
          isFetchingNextPage ? (
            <Spinner
              size="large"
              color={theme === "light" ? colors.gray[500] : colors.gray[300]} // 动态加载指示器
            />
          ) : null
        }
      />
    </Box>
  );
}
