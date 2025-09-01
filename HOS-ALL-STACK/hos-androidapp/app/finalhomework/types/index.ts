export interface Trip {
  _id?: string;
  id?: string;
  images?: string[];
  video?: string;
  authorId?: string;
  avatarUrl?: string;
  tag?: string;
  title?: string;
  description?: string;
  username?: string;
  time?: string;
  createdAt?: string;
  updatedAt?: string;
  content?: string;
  status?: "approved" | "pedding" | "rejected";
}
