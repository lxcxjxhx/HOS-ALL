import { View, Text } from "@gluestack-ui/themed";
import { StyleSheet } from "react-native";
import AISelector from "@/components/AISelector";

export default function Home() {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Select an AI Model</Text>
      <AISelector />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, alignItems: "center" },
  title: { fontSize: 24, fontWeight: "bold", marginBottom: 20 },
});
