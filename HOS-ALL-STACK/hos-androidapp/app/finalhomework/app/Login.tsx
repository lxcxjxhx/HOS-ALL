import { useNavigation } from "@react-navigation/native";
import { StackNavigationProp } from "@react-navigation/stack";
import {
  useToast,
  Toast,
  ToastTitle,
  ToastDescription,
} from "@gluestack-ui/themed";
import React, { useEffect, useState } from "react";
import {
  KeyboardAvoidingView,
  Platform,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
} from "react-native";
import { RootStackParamList } from "@/types/types"; // 注意确保路径正确
import { router } from "expo-router";
import { login } from "@/lib/api";

// 定义 navigation 类型
type LoginScreenNavigationProp = StackNavigationProp<
  RootStackParamList,
  "Login"
>;

const Login = () => {
  const navigation = useNavigation<LoginScreenNavigationProp>();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isUsernameInvalid, setIsUsernameInvalid] = useState(false);
  const [isPasswordInvalid, setIsPasswordInvalid] = useState(false);
  const toast = useToast();

  const handleLogin = async () => {
    // 暂时不处理登录逻辑，直接跳转 Home 页面
    let usernameInvalid = false;
    let passwordInvalid = false;
    if (username.length <= 0) {
      setIsUsernameInvalid(true);
      usernameInvalid = true;
    } else {
      setIsUsernameInvalid(false);
      usernameInvalid = false;
    }
    if (password.length <= 0) {
      setIsPasswordInvalid(true);
      passwordInvalid = true;
    } else {
      setIsPasswordInvalid(false);
      passwordInvalid = false;
    }
    if (usernameInvalid || passwordInvalid) {
      return;
    }
    // router.push("/");
    const res = await login(username, password);
    if (res) {
      router.push("/");
    } else {
      toast.show({
        id: Math.random().toString(),
        placement: "top",
        duration: 3000,
        containerStyle: {
          position: "relative",
          // backgroundColor: "red",
          top: 30,
        },
        render: ({ id }) => {
          const uniqueToastId = "toast-" + id;
          return (
            <Toast nativeID={uniqueToastId} action="error" variant="solid">
              <ToastDescription>账号或密码错误</ToastDescription>
            </Toast>
          );
        },
      });
      console.log("账号或密码错误");
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <Text style={styles.title}>旅游日记平台</Text>

      <TextInput
        style={styles.input}
        placeholder="用户名"
        placeholderTextColor="#aaa"
        value={username}
        onChangeText={setUsername}
        onBlur={() => setIsUsernameInvalid(username.length <= 0)}
      />
      {isUsernameInvalid && (
        <Text style={{ color: "red", marginTop: -15 }}>用户名不能为空</Text>
      )}

      <TextInput
        style={styles.input}
        placeholder="密码"
        placeholderTextColor="#aaa"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onBlur={() => setIsPasswordInvalid(password.length <= 0)}
      />
      {isPasswordInvalid && (
        <Text style={{ color: "red", marginTop: -15 }}>密码不能为空</Text>
      )}

      <TouchableOpacity style={styles.button} onPress={handleLogin}>
        <Text style={styles.buttonText}>登录</Text>
      </TouchableOpacity>
    </KeyboardAvoidingView>
  );
};

export default Login;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    paddingHorizontal: 32,
    backgroundColor: "#f2f2f2",
  },
  title: {
    fontSize: 28,
    fontWeight: "bold",
    color: "#333",
    alignSelf: "center",
    marginBottom: 40,
  },
  input: {
    height: 50,
    borderColor: "#ccc",
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 16,
    backgroundColor: "#fff",
    marginBottom: 20,
    fontSize: 16,
  },
  button: {
    backgroundColor: "#4CAF50",
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: "center",
    marginTop: 10,
  },
  buttonText: {
    color: "#fff",
    fontSize: 18,
    fontWeight: "600",
  },
});
