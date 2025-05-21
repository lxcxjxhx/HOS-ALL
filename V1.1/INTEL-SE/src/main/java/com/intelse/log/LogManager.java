package com.intelse.log;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission; // Added import
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set; // Added import
import java.util.HashSet; // Added import

public class LogManager {
    private static final String ATTACK_LOG = "/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log";
    private static final String RESULTS_LOG = "/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_results.log";
    private static final String PAYLOADS_LOG = "/home/lxcxjxhx/PROJECT/INTEL-SE/logs/payloads.log";
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void logEvent(String eventType, String message) {
        String logEntry = String.format("[%s] %s: %s\n", FORMATTER.format(LocalDateTime.now()), eventType, message);
        writeLog(ATTACK_LOG, logEntry);
        if (eventType.contains("RESULT")) {
            writeLog(RESULTS_LOG, logEntry);
        }
    }

    public static void logPayload(String payload) {
        String logEntry = String.format("[%s] PAYLOAD: %s\n", FORMATTER.format(LocalDateTime.now()), payload);
        writeLog(PAYLOADS_LOG, logEntry);
    }

    private static void writeLog(String filePath, String logEntry) {
        try {
            File file = new File(filePath);
            file.getParentFile().mkdirs();
            Files.writeString(Paths.get(filePath), logEntry, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            // Set permissions only on POSIX systems
            if (System.getProperty("os.name").toLowerCase().contains("linux")) {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                perms.add(PosixFilePermission.GROUP_READ);
                perms.add(PosixFilePermission.GROUP_WRITE);
                perms.add(PosixFilePermission.OTHERS_READ);
                Files.setPosixFilePermissions(Paths.get(filePath), perms);
            }
        } catch (Exception e) {
            System.err.println("Log write error: " + e.getMessage());
        }
    }
}
