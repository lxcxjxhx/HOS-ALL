import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  fetchTrips,
  fetchTripById,
  createTrip,
  updateTrip,
  deleteTrip,
} from "@/lib/api";
import { Trip } from "@/types";

export const useTrips = (
  query: string = "",
  authorId?: string,
  status?: string
) => {
  return useInfiniteQuery<
    { trips: Trip[] },
    Error,
    { trips: Trip[] },
    [string, string],
    number
  >({
    queryKey: ["trips", query],
    queryFn: ({ pageParam = 1 }) =>
      fetchTrips(pageParam, 10, query, authorId, status),
    initialPageParam: 1,
    getNextPageParam: (lastPage, allPages) => {
      if (lastPage.trips.length < 10) return undefined;
      return allPages.length + 1;
    },
  });
};

export const useMyTrips = (
  query: string = "",
  authorId?: string,
  status?: string
) => {
  return useInfiniteQuery<
    { trips: Trip[] },
    Error,
    { trips: Trip[] },
    [string, string],
    number
  >({
    queryKey: ["my-trips", query],
    queryFn: ({ pageParam = 1 }) =>
      fetchTrips(pageParam, 10, query, authorId, status),
    initialPageParam: 1,
    getNextPageParam: (lastPage, allPages) => {
      if (lastPage.trips.length < 10) return undefined;
      return allPages.length + 1;
    },
  });
};

export const useTrip = (id: string) => {
  return useQuery({
    queryKey: ["trip", id],
    queryFn: () => fetchTripById(id),
  });
};

export const useCreateTrip = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createTrip,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["trips"] });
    },
  });
};

export const useUpdateTrip = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, trip }: { id: string; trip: Partial<Trip> }) =>
      updateTrip(id, trip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["my-trips"] });
    },
  });
};

export const useDeleteTrip = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deleteTrip,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["my-trips"] });
    },
  });
};
