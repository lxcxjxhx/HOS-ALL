import { useState } from "react";
import { View, ScrollView, TextInput } from "react-native";
import { Text, Button, ButtonText } from "@gluestack-ui/themed";
import { StyleSheet } from "react-native";
import ChatBubble from "@/components/ChatBubble";
import { useLocalSearchParams } from "expo-router";

interface Message {
  id: string;
  text: string;
  isUser: boolean;
}

export default function Chat() {
  const { aiModel } = useLocalSearchParams();
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState("");

  // Function to send message to AI API (mocked for now)
  const sendMessage = async () => {
    if (!inputText.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      text: inputText,
      isUser: true,
    };

    setMessages([...messages, userMessage]);
    setInputText("");

    // Simulate API call to AI service
    try {
      // Replace with actual API endpoint, e.g., xAI's Grok API
      // const response = await fetch("https://api.x.ai/grok", {
      //   method: "POST",
      //   headers: { "Content-Type": "application/json" },
      //   body: JSON.stringify({ message: inputText, model: aiModel }),
      // });
      // const data = await response.json();

      // Mocked response for demonstration
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        text: `Response from ${aiModel}: This is a mock reply to "${inputText}"`,
        isUser: false,
      };

      setMessages((prev) => [...prev, aiResponse]);
    } catch (error) {
      console.error("API Error:", error);
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        text: "Error: Could not connect to AI service",
        isUser: false,
      };
      setMessages((prev) => [...prev, errorMessage]);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Chatting with {aiModel}</Text>
      <ScrollView style={styles.chatArea}>
        {messages.map((msg) => (
          <ChatBubble key={msg.id} message={msg} />
        ))}
      </ScrollView>
      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          value={inputText}
          onChangeText={setInputText}
          placeholder="Type your message..."
        />
        <Button style={styles.sendButton} onPress={sendMessage}>
          <ButtonText>Send</ButtonText>
        </Button>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 10 },
  title: { fontSize: 20, fontWeight: "bold", marginBottom: 10 },
  chatArea: { flex: 1, marginBottom: 10 },
  inputContainer: {
    flexDirection: "row",
    alignItems: "center",
    borderTopWidth: 1,
    borderColor: "#ccc",
    padding: 10,
  },
  input: {
    flex: 1,
    borderWidth: 1,
    borderColor: "#ccc",
    borderRadius: 5,
    padding: 10,
    marginRight: 10,
  },
  sendButton: { backgroundColor: "#007AFF" },
});
