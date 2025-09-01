import { Button, ButtonText } from "@gluestack-ui/themed";
import { StyleSheet } from "react-native";
import { useRouter } from "expo-router";

export default function AISelector() {
  const router = useRouter();

  const handleSelectAI = (aiModel: string) => {
    // Navigate to chat page with selected AI model
    router.push({ pathname: "/chat", params: { aiModel } });
  };

  return (
    <>
      <Button style={styles.button} onPress={() => handleSelectAI("Grok")}>
        <ButtonText>Grok</ButtonText>
      </Button>
      <Button style={styles.button} onPress={() => handleSelectAI("ChatGPT")}>
        <ButtonText>ChatGPT</ButtonText>
      </Button>
    </>
  );
}

const styles = StyleSheet.create({
  button: { marginVertical: 10, width: "80%", backgroundColor: "#007AFF" },
});
