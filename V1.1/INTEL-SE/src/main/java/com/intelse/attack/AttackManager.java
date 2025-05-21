package com.intelse.attack;

import com.intelse.config.ConfigManager;
import com.intelse.log.LogManager;

public class AttackManager {
    private final PayloadGenerator payloadGenerator;
    private final NetworkClient networkClient;
    private String targetIp;

    public AttackManager() {
        this.payloadGenerator = new PayloadGenerator();
        this.networkClient = new NetworkClient();
        this.targetIp = ConfigManager.getInstance().getTargetIp();
    }

    public String generatePayload(String url, String vulnType) {
        String payload = payloadGenerator.generate(url, vulnType);
        LogManager.logEvent("ATTACK_RESULT", "Payload generated: " + payload);
        return "Generated payload: " + payload;
    }

    public String runAttack() {
        if (targetIp == null || targetIp.isEmpty()) {
            String error = "No target IP configured";
            LogManager.logEvent("ATTACK_ERROR", error);
            return error;
        }
        try {
            String result = networkClient.sendAttack(targetIp);
            LogManager.logEvent("ATTACK_RESULT", "Attack executed on " + targetIp + ": " + result);
            return result;
        } catch (Exception e) {
            String error = "Attack failed: " + e.getMessage();
            LogManager.logEvent("ATTACK_ERROR", error);
            return error;
        }
    }

    public void setTargetIp(String ip) {
        this.targetIp = ip;
        ConfigManager.getInstance().setTargetIp(ip);
    }
}
