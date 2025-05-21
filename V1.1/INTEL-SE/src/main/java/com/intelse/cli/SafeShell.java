package com.intelse.cli;

import com.intelse.log.LogManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class SafeShell {
    private static final List<String> BLACKLISTED_COMMANDS = Arrays.asList(
        "rm", "sudo", "dd", "mkfs", "reboot", "halt"
    );

    public String executeShellCommand(String command) throws Exception {
        // Check for blacklisted commands
        String cmd = command.split("\\s+")[0].toLowerCase();
        if (BLACKLISTED_COMMANDS.contains(cmd) || command.contains("&") || command.contains("|")) {
            String error = "Command '" + cmd + "' is restricted for safety";
            LogManager.logEvent("CLI_ERROR", error);
            return error;
        }

        // Execute safe command using ProcessBuilder
        try {
            ProcessBuilder pb = new ProcessBuilder(command.split("\\s+"));
            pb.redirectErrorStream(true); // Combine stdout and stderr
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            reader.close();
            int exitCode = process.waitFor();
            String result = output.toString();
            String logMessage = "Shell command executed: " + command + ", exit code: " + exitCode;
            LogManager.logEvent("COMMAND_EXEC", logMessage);
            return result.isEmpty() ? "Command executed successfully" : result;
        } catch (Exception e) {
            String error = "Shell command error: " + e.getMessage();
            LogManager.logEvent("CLI_ERROR", error);
            return error;
        }
    }
}
