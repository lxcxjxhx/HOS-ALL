import { GluestackUIProvider } from "@gluestack-ui/themed";
import { config } from "@gluestack-ui/config";
import { Tabs } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { StyleSheet } from "react-native";

export default function Layout() {
  return (
    <GluestackUIProvider config={config}>
      <SafeAreaView style={styles.container}>
        <Tabs
          screenOptions={{
            tabBarActiveTintColor: "#007AFF",
            tabBarStyle: { backgroundColor: "#fff" },
          }}
        >
          <Tabs.Screen
            name="index"
            options={{ title: "Home", tabBarLabel: "Home" }}
          />
          <Tabs.Screen
            name="chat"
            options={{ title: "Chat", tabBarLabel: "Chat" }}
          />
          <Tabs.Screen
            name="settings"
            options={{ title: "Settings", tabBarLabel: "Settings" }}
          />
        </Tabs>
      </SafeAreaView>
    </GluestackUIProvider>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f5f5f5" },
});
