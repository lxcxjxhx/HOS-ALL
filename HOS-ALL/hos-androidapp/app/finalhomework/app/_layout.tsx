import { config } from "@gluestack-ui/config";
import { GluestackUIProvider } from "@gluestack-ui/themed";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Stack, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import { getToken } from "@/utils/token";

const queryClient = new QueryClient();

export default function RootLayout() {
  const [isReady, setIsReady] = useState(false);
  const [isLogin, setIsLogin] = useState(false);
  const router = useRouter();

  useEffect(() => {
    getToken().then((token) => {
      setIsLogin(!!token);
      setIsReady(true);
      // if (token) {
      //   router.replace("/(tabs)");
      // } else {
      //   router.replace("/Login");
      // }
    });
  }, []);

  if (!isReady) return null;

  return (
    <GluestackUIProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <Stack initialRouteName={isLogin ? "(tabs)" : "Login"}>
          <Stack.Screen name="Login" options={{ title: "" }} />
          <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
          <Stack.Screen name="+not-found" />
          <Stack.Screen
            name="publish"
            options={{
              headerShown: true,
              title: "",
              headerBackButtonDisplayMode: "generic",
            }}
          />
          <Stack.Screen
            name="detail/[id]"
            options={{
              headerShown: true,
              title: "",
              headerBackButtonDisplayMode: "generic",
            }}
          />
        </Stack>
      </QueryClientProvider>
    </GluestackUIProvider>
  );
}
