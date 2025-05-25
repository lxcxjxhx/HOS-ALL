import { View, Text } from "@gluestack-ui/themed";
import { StyleSheet } from "react-native";

interface Message {
  id: string;
  text: string;
  isUser: boolean;
}

interface ChatBubbleProps {
  message: Message;
}

export default function ChatBubble({ message }: ChatBubbleProps) {
  return (
    <View
      style={[
        styles.bubble,
        message.isUser ? styles.userBubble : styles.aiBubble,
      ]}
    >
      <Text style={styles.text}>{message.text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  bubble: {
    maxWidth: "80%",
    padding: 10,
    borderRadius: 10,
    marginVertical: 5,
  },
  userBubble: {
    backgroundColor: "#007AFF",
    alignSelf: "flex-end",
    marginLeft: 10,
  },
  aiBubble: {
    backgroundColor: "#e5e5ea",
    alignSelf: "flex-start",
    marginRight: 10,
  },
  text: { color: "#000" },
});
