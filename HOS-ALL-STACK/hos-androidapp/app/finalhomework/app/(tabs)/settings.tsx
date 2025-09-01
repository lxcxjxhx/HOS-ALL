import React, { createContext, useContext, useState, useEffect } from "react";
import { View, Text, Switch, StyleSheet, TouchableOpacity } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useNavigation } from "@react-navigation/native";

// 定义主题上下文类型
type Theme = "light" | "dark";
interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

// 主题提供程序组件
export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [theme, setTheme] = useState<Theme>("light");

  useEffect(() => {
    const loadTheme = async () => {
      try {
        const savedTheme = await AsyncStorage.getItem("theme");
        if (savedTheme) {
          setTheme(savedTheme as Theme);
        }
      } catch (error) {
        console.error("加载主题失败：", error);
      }
    };
    loadTheme();
  }, []);

  const toggleTheme = async () => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    try {
      await AsyncStorage.setItem("theme", newTheme);
    } catch (error) {
      console.error("保存主题失败：", error);
    }
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

// 钩住以使用主题
export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
};

// 设置屏幕
export default function Settings() {
  const { theme, toggleTheme } = useTheme();
  const navigation = useNavigation();

  const handleLogout = async () => {
    try {
      // Clear all AsyncStorage data
      await AsyncStorage.clear();
      // Navigate to Login screen
      navigation.reset({
        index: 0,
        routes: [{ name: "Login" }],
      });
    } catch (error) {
      console.error("登出失败：", error);
    }
  };

  const styles = StyleSheet.create({
    container: {
      flex: 1,
      padding: 16,
      backgroundColor: theme === "light" ? "#fff" : "#333",
    },
    title: {
      fontSize: 24,
      fontWeight: "bold",
      marginBottom: 16,
      color: theme === "light" ? "#000" : "#fff",
    },
    row: {
      flexDirection: "row",
      justifyContent: "space-between",
      alignItems: "center",
      paddingVertical: 8,
    },
    label: {
      fontSize: 16,
      color: theme === "light" ? "#000" : "#fff",
    },
    logoutButton: {
      marginTop: 20,
      padding: 12,
      backgroundColor: theme === "light" ? "#ff4444" : "#cc0000",
      borderRadius: 8,
      alignItems: "center",
    },
    logoutButtonText: {
      color: "#fff",
      fontSize: 16,
      fontWeight: "bold",
    },
  });

  return (
    <View style={styles.container}>
      <Text style={styles.title}>设置</Text>
      <View style={styles.row}>
        <Text style={styles.label}>黑暗模式</Text>
        <Switch
          value={theme === "dark"}
          onValueChange={toggleTheme}
          trackColor={{ false: "#767577", true: "#ffd33d" }}
          thumbColor={theme === "dark" ? "#f4f3f4" : "#f4f3f4"}
        />
      </View>
      <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
        <Text style={styles.logoutButtonText}>登出</Text>
      </TouchableOpacity>
    </View>
  );
}
