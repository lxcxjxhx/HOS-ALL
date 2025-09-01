import React, { useState, useEffect } from "react";
import {
  FlatList,
  Dimensions,
  StyleSheet,
  TouchableOpacity,
  View,
} from "react-native";
import { Box, Input, InputField, Spinner, Text } from "@gluestack-ui/themed";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useTrips } from "@/hooks/useTrips";
import { TripCard } from "@/components/TripCard";
import colors from "tailwindcss/colors";
import { useTheme } from "./settings";

const { width: WINDOW_WIDTH } = Dimensions.get("window");
const SEARCH_HISTORY_KEY = "@search_history";

export default function Search() {
  const { theme } = useTheme();
  const [query, setQuery] = useState("");
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useTrips(query);
  const numColumns = 2;
  const trips = data?.pages.flatMap((page) => page.trips) || [];
  const remainder = trips.length % numColumns;
  const cardWidth = Math.min(WINDOW_WIDTH * 0.45, 320);
  const filledTrips = [...trips];
  if (remainder !== 0) {
    const placeholders = Array.from({ length: numColumns - remainder }).map(
      (_, i) => ({ id: `placeholder-${i}`, isPlaceholder: true })
    );
    filledTrips.push(...(placeholders as any));
  }

  // Load search history from AsyncStorage when component mounts
  useEffect(() => {
    const loadSearchHistory = async () => {
      try {
        const history = await AsyncStorage.getItem(SEARCH_HISTORY_KEY);
        if (history) {
          setSearchHistory(JSON.parse(history));
        }
      } catch (error) {
        console.error("Failed to load search history:", error);
      }
    };
    loadSearchHistory();
  }, []);

  // Save search query to history
  const saveSearchQuery = async (newQuery: string) => {
    if (!newQuery.trim()) return;
    try {
      const updatedHistory = [
        newQuery,
        ...searchHistory.filter((q) => q !== newQuery).slice(0, 9), // Keep max 10 unique queries
      ];
      setSearchHistory(updatedHistory);
      await AsyncStorage.setItem(
        SEARCH_HISTORY_KEY,
        JSON.stringify(updatedHistory)
      );
    } catch (error) {
      console.error("Failed to save search history:", error);
    }
  };

  // Handle search input change
  const handleSearchChange = (text: string) => {
    setQuery(text);
    if (text.trim()) {
      saveSearchQuery(text.trim());
    }
  };

  // Handle selecting a history item
  const handleHistorySelect = (historyQuery: string) => {
    setQuery(historyQuery);
    saveSearchQuery(historyQuery); // Re-save to update order
  };

  // Dynamic styles
  const styles = StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: theme === "light" ? colors.white : "#333",
    },
    input: {
      backgroundColor: theme === "light" ? "#f9f9f9" : "#444",
      borderColor: theme === "light" ? colors.gray[300] : colors.gray[600],
      borderWidth: 1,
      borderRadius: 8,
    },
    inputField: {
      color: theme === "light" ? colors.gray[900] : colors.white,
    },
    placeholder: {
      color: theme === "light" ? colors.gray[400] : colors.gray[500],
    },
    messageText: {
      fontSize: 16,
      color: theme === "light" ? colors.gray[700] : colors.gray[200],
    },
    historyItem: {
      padding: 10,
      borderBottomWidth: 1,
      borderBottomColor:
        theme === "light" ? colors.gray[200] : colors.gray[600],
    },
    historyText: {
      fontSize: 16,
      color: theme === "light" ? colors.gray[900] : colors.gray[200],
    },
    spinner: {
      color: theme === "light" ? colors.gray[500] : colors.gray[300],
    },
    flatListContent: {
      alignItems: "center",
      paddingVertical: 10,
    },
    columnWrapper: {
      justifyContent: "center",
      gap: 10,
    },
  });

  return (
    <Box className="flex-1 p-4" style={styles.container}>
      <Input variant="outline" className="mb-4" style={styles.input}>
        <InputField
          placeholder="Search trips..."
          value={query}
          onChangeText={handleSearchChange}
          style={styles.inputField}
          placeholderTextColor={styles.placeholder.color}
        />
      </Input>
      {query.trim() === "" ? (
        searchHistory.length > 0 ? (
          <Box className="flex-1">
            <Text style={styles.messageText} className="mb-2">
              Recent Searches
            </Text>
            <FlatList
              data={searchHistory}
              renderItem={({ item }) => (
                <TouchableOpacity
                  style={styles.historyItem}
                  onPress={() => handleHistorySelect(item)}
                >
                  <Text style={styles.historyText}>{item}</Text>
                </TouchableOpacity>
              )}
              keyExtractor={(item, index) => `history-${index}`}
              showsVerticalScrollIndicator={false}
            />
          </Box>
        ) : (
          <Box className="flex-1 justify-center items-center">
            <Text style={styles.messageText}>
              Enter a search query to find trips
            </Text>
          </Box>
        )
      ) : trips.length === 0 && !isFetchingNextPage ? (
        <Box className="flex-1 justify-center items-center">
          <Text style={styles.messageText}>No trips found</Text>
        </Box>
      ) : (
        <FlatList
          data={filledTrips}
          renderItem={({ item }) => {
            if ((item as any).isPlaceholder) {
              return <View style={{ width: cardWidth, height: 0 }} />;
            }
            return <TripCard trip={item} />;
          }}
          keyExtractor={(item) => item._id}
          numColumns={numColumns}
          onEndReached={() =>
            hasNextPage && !isFetchingNextPage && fetchNextPage()
          }
          onEndReachedThreshold={0.5}
          ListFooterComponent={
            isFetchingNextPage ? (
              <Spinner size="large" style={styles.spinner} />
            ) : null
          }
          contentContainerStyle={styles.flatListContent}
          columnWrapperStyle={styles.columnWrapper}
          showsVerticalScrollIndicator={false}
        />
      )}
    </Box>
  );
}
