import React from "react";
import { Tabs } from "expo-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SafeAreaView } from "react-native-safe-area-context";
import Ionicons from "@expo/vector-icons/Ionicons";
import { useRouter } from "expo-router";
import { TouchableOpacity, Text } from "react-native";
import { useTheme, ThemeProvider } from "./settings"; // 导入 useTheme 和 ThemeProvider
import colors from "tailwindcss/colors"; // 导入 Tailwind 颜色

const queryClient = new QueryClient();

// 新组件：包含 Tabs 和主题相关的样式
const TabNavigator = () => {
  const { theme } = useTheme(); // 在 ThemeProvider 内部使用 useTheme
  const router = useRouter();

  return (
    <Tabs
      screenOptions={{
        tabBarActiveTintColor: theme === "light" ? "#ffd33d" : "#facc15", // 动态激活颜色
        tabBarInactiveTintColor: theme === "light" ? "#888" : "#aaa", // 动态未激活颜色
        tabBarStyle: {
          backgroundColor: theme === "light" ? colors.white : "#333", // 动态 TabBar 背景
          borderTopColor:
            theme === "light" ? colors.gray[200] : colors.gray[700], // 动态边框
          height: 60,
        },
        headerShown: true,
        headerStyle: {
          height: 60, // 设置 header 高度
        },
        headerTitleStyle: {
          fontSize: 18,
        },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          tabBarLabel: "主页",
          title: "",
          tabBarIcon: ({ color, focused }) => (
            <Ionicons
              name={focused ? "home-sharp" : "home-outline"}
              color={color}
              size={24}
            />
          ),
        }}
      />
      <Tabs.Screen
        name="search"
        options={{
          tabBarLabel: "Search",
          title: "",
          tabBarShowLabel: true,
          href: null,
          tabBarIcon: ({ color, focused }) => (
            <Ionicons
              name={focused ? "compass" : "compass-outline"}
              color={color}
              size={24}
            />
          ),
        }}
      />
      <Tabs.Screen
        name="publish-placeholder"
        options={{
          tabBarLabel: "发布",
          tabBarIcon: ({ color, focused }) => (
            <Ionicons
              name={focused ? "add-circle" : "add-circle-outline"}
              color={color}
              size={24}
            />
          ),
          tabBarButton: (props) => (
            <TouchableOpacity
              delayLongPress={500}
              {...props}
              onPress={() => router.push("/publish")}
              style={{
                flex: 1,
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Ionicons
                name={"add-circle-outline"}
                color={
                  props.accessibilityState?.selected
                    ? theme === "light"
                      ? "#ffd33d"
                      : "#facc15" // 动态图标颜色
                    : theme === "light"
                    ? "#888"
                    : "#aaa"
                }
                size={28}
              />
              <Text
                style={{
                  fontSize: 12,
                  color: props.accessibilityState?.selected
                    ? theme === "light"
                      ? "#ffd33d"
                      : "#facc15" // 动态文字颜色
                    : theme === "light"
                    ? "#888"
                    : "#aaa",
                }}
              >
                发布
              </Text>
            </TouchableOpacity>
          ),
        }}
      />
      <Tabs.Screen
        name="my-trips"
        options={{
          tabBarLabel: "我的发布",
          title: "",
          tabBarIcon: ({ color, focused }) => (
            <Ionicons
              name={focused ? "person" : "person-outline"}
              color={color}
              size={24}
            />
          ),
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          tabBarLabel: "设置",
          title: "",
          tabBarIcon: ({ color, focused }) => (
            <Ionicons
              name={focused ? "settings" : "settings-outline"}
              color={color}
              size={24}
            />
          ),
        }}
      />
    </Tabs>
  );
};

export default function Layout() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <SafeAreaView
          style={{
            flex: 1,
            backgroundColor: colors.white, // 默认白色，TabNavigator 控制内容区域
          }}
          edges={["bottom"]}
        >
          <TabNavigator />
        </SafeAreaView>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
