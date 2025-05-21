package com.intelse.ai;

import com.intelse.config.ConfigManager;
import com.intelse.log.LogManager;

public class AIQueryHandler {
    private final String model;

    public AIQueryHandler() {
        this.model = ConfigManager.getInstance().getAIModel();
    }

    public String processQuery(String query) {
        // Mock response until real AI API is integrated
        String response = "AI Response: Query '" + query + "' processed using model " + model;
        LogManager.logEvent("ATTACK_RESULT", response);
        return response;
    }
}
