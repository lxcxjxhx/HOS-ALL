package com.intelse.attack;

import com.intelse.log.LogManager;

public class PayloadGenerator {
    public String generate(String url, String vulnType) {
        String payload;
        switch (vulnType.toLowerCase()) {
            case "sql":
                payload = "SELECT * FROM users WHERE 1=1 --";
                break;
            case "xss":
                payload = "<script>alert('XSS');</script>";
                break;
            default:
                payload = "Unsupported vulnerability type: " + vulnType;
                LogManager.logEvent("LOG_ERROR", payload);
                return payload;
        }
        LogManager.logPayload(payload);
        return payload;
    }
}
