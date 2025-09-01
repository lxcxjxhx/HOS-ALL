-- MySQL dump 10.13  Distrib 8.0.41, for Linux (x86_64)
--
-- Host: localhost    Database: travel_app
-- ------------------------------------------------------
-- Server version	8.0.41-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `favorites`
--

DROP TABLE IF EXISTS `favorites`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `favorites` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `post_id` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`,`post_id`),
  KEY `post_id` (`post_id`),
  CONSTRAINT `favorites_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `favorites_ibfk_2` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `favorites`
--

LOCK TABLES `favorites` WRITE;
/*!40000 ALTER TABLE `favorites` DISABLE KEYS */;
/*!40000 ALTER TABLE `favorites` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `likes`
--

DROP TABLE IF EXISTS `likes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `likes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `post_id` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`,`post_id`),
  KEY `post_id` (`post_id`),
  CONSTRAINT `likes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `likes_ibfk_2` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `likes`
--

LOCK TABLES `likes` WRITE;
/*!40000 ALTER TABLE `likes` DISABLE KEYS */;
/*!40000 ALTER TABLE `likes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `post_rankings`
--

DROP TABLE IF EXISTS `post_rankings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `post_rankings` (
  `post_id` int NOT NULL,
  `score` decimal(10,2) NOT NULL DEFAULT '0.00',
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`post_id`),
  CONSTRAINT `post_rankings_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `post_rankings`
--

LOCK TABLES `post_rankings` WRITE;
/*!40000 ALTER TABLE `post_rankings` DISABLE KEYS */;
/*!40000 ALTER TABLE `post_rankings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `posts`
--

DROP TABLE IF EXISTS `posts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `posts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) DEFAULT NULL,
  `content` text,
  `image` varchar(512) DEFAULT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `reason` text,
  `user_id` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `posts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `posts`
--

LOCK TABLES `posts` WRITE;
/*!40000 ALTER TABLE `posts` DISABLE KEYS */;
INSERT INTO `posts` VALUES (1,'1','eJwzBAAAMgAy',NULL,'pending',NULL,7,'2025-05-05 13:52:10','2025-05-05 13:52:10'),(2,'1','eJwzBAAAMgAy',NULL,'pending',NULL,7,'2025-05-05 13:52:25','2025-05-05 13:52:25'),(3,'1','eJwzBAAAMgAy',NULL,'pending',NULL,7,'2025-05-05 13:53:46','2025-05-05 13:53:46');
/*!40000 ALTER TABLE `posts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_logins`
--

DROP TABLE IF EXISTS `user_logins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_logins` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `login_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` varchar(45) DEFAULT NULL,
  `device_info` text,
  `session_id` varchar(255) DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `jwt_secret` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_id` (`session_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `user_logins_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_logins`
--

LOCK TABLES `user_logins` WRITE;
/*!40000 ALTER TABLE `user_logins` DISABLE KEYS */;
INSERT INTO `user_logins` VALUES (2,7,'2025-05-05 13:51:43','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Nywicm9sZSI6InVzZXIiLCJpYXQiOjE3NDY0NTMxMDMsImV4cCI6MTc0NjQ1NjcwM30.HNQ37xwxs0Fr3f9WnOADtdy9wkm5txo_GqdPyiKTxEc','2025-05-05 14:51:43','e02bd3aaa4f6ffdc4102da918e1854898db4f07d2887c3f095147e624b5c426dd394668f606a25820ce81d396cbbee93b824e4b52da6c50fa785e2c18f43c517'),(3,7,'2025-05-05 13:52:03','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Nywicm9sZSI6InVzZXIiLCJpYXQiOjE3NDY0NTMxMjMsImV4cCI6MTc0NjQ1NjcyM30.wKzPOSkEw7P5Lb7s1lqOOuEOJpoMEPHvhtktS48MQS8','2025-05-05 14:52:03','68833b57f5742d25c8e878160ee7aebd8606cafdfa963dda27a394ed5da3f447fd221f3dc443e9a65325afd4a50e5082d83d5ad37998b84f4433a1a94d8452bb'),(4,8,'2025-05-05 13:53:03','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OCwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzQ2NDUzMTgzLCJleHAiOjE3NDY0NTY3ODN9.pLheXTCWOeUMCIfCelh3HgwRxrzu531TdGTLRkNe0HQ','2025-05-05 14:53:03','68ef4e0f2d7afbf539b499c63c2df51398e84ba132471ddb32522f80ba09be0af8e395687c264c6c331bc0211721a6ac755a7d66a7fc9b446238e1257ccd638b'),(5,8,'2025-05-05 13:53:15','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OCwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzQ2NDUzMTk1LCJleHAiOjE3NDY0NTY3OTV9.618E6nxQR4Dnr0En_EezHg0_3kBlDgKgYRPIwHGZFqY','2025-05-05 14:53:15','57767367b20fe7d3ca2784a806f99e43ed637cc5098b0a846dfe7b1f1d8241d744c880b63adf05dbc6dc2c8c8c99f19ce3ec82876423236437b64256010f4603'),(6,7,'2025-05-05 13:53:29','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Nywicm9sZSI6InVzZXIiLCJpYXQiOjE3NDY0NTMyMDksImV4cCI6MTc0NjQ1NjgwOX0.jjJ38Td_8fBXzCZ_03DtoxZrNnuJKuinoTTx4Bq9cdw','2025-05-05 14:53:29','40c715bffe2176bdfbdfb8cf036554da56be8aefe79d45f2a5c3227c5a3b3e699b432ddddc32c1dde0acff54434019489a251f41b0415e4066396296154d59e1'),(7,7,'2025-05-05 14:06:45','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Nywicm9sZSI6InVzZXIiLCJpYXQiOjE3NDY0NTQwMDUsImV4cCI6MTc0NjQ1NzYwNX0.3093NU-ZTDb3kULEpLBwZjPRgcLr_n_CiJ4vyrwnYgU','2025-05-05 15:06:45','d2298da2904a2f7e481aaf3510ef67f2c92f10aa4a04bed2cf41e404c77bd68de0dd18228c45fd7d2ba12be61636bf7a53f0de2055a4d7f3ab2d541f2be3faaf'),(8,7,'2025-05-05 14:21:40','::ffff:127.0.0.1','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Nywicm9sZSI6InVzZXIiLCJpYXQiOjE3NDY0NTQ5MDAsImV4cCI6MTc0NjQ1ODUwMH0.TIg-C0XsC6Ai6oIWteeWJs-dpvC_6GTfUyL8bPeU1Cw','2025-05-05 15:21:40','3b1819644c440c464dbc1885229637c687b8fb9abd45ff792dd0f38bcc2b8eb8b0a73f9a2a635137c3538e05c50ed54bb9a7a643812f946f807c1405b5917f4e');
/*!40000 ALTER TABLE `user_logins` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_preferences`
--

DROP TABLE IF EXISTS `user_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_preferences` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `post_id` int NOT NULL,
  `visited_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `action` enum('view','like','favorite') DEFAULT 'view',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `post_id` (`post_id`),
  CONSTRAINT `user_preferences_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_preferences_ibfk_2` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_preferences`
--

LOCK TABLES `user_preferences` WRITE;
/*!40000 ALTER TABLE `user_preferences` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_preferences` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `phone_number` varchar(20) NOT NULL,
  `gender` enum('男','女','其他') DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `birth_date` date DEFAULT NULL,
  `bio` text,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `role` enum('admin','user') NOT NULL DEFAULT 'user',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `unique_phone_number` (`phone_number`),
  UNIQUE KEY `username_2` (`username`),
  UNIQUE KEY `phone_number` (`phone_number`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (2,'TEST','$2a$10$sHtsfWfi1Q2Use.ozSq7A.6uvofdDF7lvuNFUH3sDaTuQ/nJtbiKq','10000000001','男','test@qq.com','2025-05-04',NULL,'2025-05-04 14:29:51','2025-05-04 14:29:51','user'),(3,'admin','$2a$10$2W4DHQ2xygukXsgWT/0rveDq35VxKAOYScn6tG7fMjJ8h9Hvhq.xS','admin','男','admin@qq.com','2025-05-04',NULL,'2025-05-04 14:31:34','2025-05-04 14:31:34','admin'),(4,'man','$2a$10$OwjeVYLXqUFk7WeaIG0gheVPpLCi.HdjHLwz4XpjevZTIy0IGpc4e','man','男','man@man.man','2025-05-05',NULL,'2025-05-05 05:50:34','2025-05-05 05:50:34','user'),(5,'10000000002','$2a$10$RksOKy8X4uBf5M1T6/E58OTTgb5dU18vTAhnlyTVTcjaxjSRqx5Mi','10000000002','男','test2@test.com','2025-05-05',NULL,'2025-05-05 11:39:28','2025-05-05 11:39:28','admin'),(6,'10000000003','$2a$10$/vtOYeyLwmsI7WEHutf5cuspCVkOQ84icqk4OxEubHqz2QKKFphfu','10000000003','男','test@test.com','2025-05-05',NULL,'2025-05-05 12:12:27','2025-05-05 12:12:27','admin'),(7,'10000000005','$2a$10$hdgdq70y7pMy75GBAE/yuOq/x9YJhqV/AzxTg/Vh778Blpjq1/6va','10000000005','男','TEST@TEST.COM','2025-05-05',NULL,'2025-05-05 13:51:43','2025-05-05 13:51:43','user'),(8,'10000000009','$2a$10$F0TEpAogHmyerp8oNWJxTumL2ccJsVuugRgB/0AChmCSTDSKhG93.','10000000009','男','TEST@TEST.COM','2025-05-05',NULL,'2025-05-05 13:53:03','2025-05-05 13:53:03','admin');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `verification_codes`
--

DROP TABLE IF EXISTS `verification_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `verification_codes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `code` varchar(6) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `verification_codes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `verification_codes`
--

LOCK TABLES `verification_codes` WRITE;
/*!40000 ALTER TABLE `verification_codes` DISABLE KEYS */;
/*!40000 ALTER TABLE `verification_codes` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-05-05 22:39:54
