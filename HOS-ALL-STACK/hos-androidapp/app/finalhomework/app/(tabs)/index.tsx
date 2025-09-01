import "@/global.css";
import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Dimensions,
  FlatList,
  RefreshControl,
  View,
  StyleSheet,
  TouchableOpacity,
} from "react-native";
import MasonryList from "@react-native-seoul/masonry-list";
import { Box, Input, InputField, Spinner, Text } from "@gluestack-ui/themed";
import { useTrips } from "@/hooks/useTrips";
import { TripCard } from "@/components/TripCard";
import colors from "tailwindcss/colors";
import { router, useNavigation } from "expo-router";
import { useTheme } from "./settings"; // 导入 useTheme
import { Stack } from "expo-router";
import { Trip } from "@/types";

const { width: WINDOW_WIDTH } = Dimensions.get("window");

export default function Home() {
  const { theme } = useTheme(); // 获取当前主题
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, refetch } =
    useTrips("", undefined, "approved");
  const numColumns = 2;
  const trips = data?.pages.flatMap((page) => page.trips) || [];
  const filledTrips = [...trips];
  const remainder = trips.length % numColumns;
  const cardWidth = Math.min(WINDOW_WIDTH * 0.45, 320);
  const navigation = useNavigation();
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [reachedBottom, setReachedBottom] = useState(false);

  // useEffect(() => {
  //   const unsubscribe = navigation.addListener("focus", () => {
  //     // Fetch or refresh data here
  //   });
  //   return unsubscribe;
  // }, [navigation]);

  const onRefresh = React.useCallback(async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  }, [refetch]);

  const handleSearchPress = () => {
    router.push("./search");
  };

  if (remainder !== 0) {
    const placeholders = Array.from({ length: numColumns - remainder }).map(
      (_, i) => ({ id: `placeholder-${i}`, isPlaceholder: true })
    );
    filledTrips.push(...(placeholders as any));
  }

  // 动态样式
  const styles = StyleSheet.create({
    bottomText: {
      textAlign: "center",
      padding: 16,
      color: theme === "light" ? colors.gray[500] : colors.gray[300], // 文字颜色根据主题调整
      fontSize: 16,
    },
    input: {
      backgroundColor: theme === "light" ? "#f9f9f9" : "#444", // 输入框背景
      borderColor: theme === "light" ? colors.gray[300] : colors.gray[600], // 边框颜色
      color: theme === "light" ? colors.gray[900] : colors.white, // 文字颜色
    },
    container: {
      flex: 1,
      backgroundColor: theme === "light" ? colors.white : "#333", // 动态背景色
      paddingLeft: 0,
      paddingRight: 0,
      paddingTop: 10,
      paddingBottom: 0,
    },
  });

  return (
    <View style={styles.container}>
      <Stack.Screen
        options={{
          headerStyle: {
            height: 60,
          },
          headerTitleStyle: {
            fontSize: 18,
          },
        }}
      />
      <Box className="px-4">
        <TouchableOpacity onPress={handleSearchPress} activeOpacity={0.7}>
          <Input
            variant="outline"
            className="mb-4"
            isReadOnly
            style={styles.input} // 应用动态输入框样式
          >
            <InputField
              placeholder="Search trips..."
              value={searchQuery}
              onChangeText={setSearchQuery}
              editable={false}
              style={{
                color: theme === "light" ? colors.gray[900] : colors.white, // 输入文字颜色
                placeholderTextColor:
                  theme === "light" ? colors.gray[400] : colors.gray[500], // 占位文字颜色
              }}
            />
          </Input>
        </TouchableOpacity>
      </Box>
      <MasonryList
        data={trips}
        renderItem={({ item, i }: { item: unknown; i: number }) => {
          if ((item as any).isPlaceholder) {
            return <View style={{ width: cardWidth, height: 0 }} />;
          }
          return <TripCard trip={item as Trip} />;
        }}
        keyExtractor={(item, index) => `${item._id}-${index}`}
        numColumns={numColumns}
        onEndReached={() => {
          if (hasNextPage && !isFetchingNextPage) {
            fetchNextPage();
          } else if (!hasNextPage) {
            setReachedBottom(true);
            setTimeout(() => setReachedBottom(false), 2000);
          }
        }}
        onEndReachedThreshold={0.5}
        // refreshControl={
        //   <RefreshControl
        //     refreshing={refreshing}
        //     onRefresh={onRefresh}
        //     colors={[theme === "light" ? colors.blue[500] : colors.blue[300]]} // 刷新指示器颜色
        //     tintColor={theme === "light" ? colors.blue[500] : colors.blue[300]}
        //   />
        // }
        refreshing={refreshing}
        onRefresh={onRefresh}
        ListFooterComponent={
          <>
            {isFetchingNextPage && (
              <Spinner
                size="large"
                color={theme === "light" ? colors.gray[500] : colors.gray[300]} // 加载指示器颜色
              />
            )}
            {reachedBottom && (
              <Text style={styles.bottomText}>已经到底啦~</Text>
            )}
          </>
        }
        contentContainerStyle={{
          alignSelf: "stretch",
          // width: "95%",
          paddingHorizontal: 5,
          // paddingVertical: 10,
        }}
        // containerStyle={{
        //   // backgroundColor: "red",
        //   paddingVertical: 0,
        // }}
        // columnWrapperStyle={{
        //   justifyContent: "center",
        //   gap: 10,
        // }}
        showsVerticalScrollIndicator={false}
      />
    </View>
  );
}
