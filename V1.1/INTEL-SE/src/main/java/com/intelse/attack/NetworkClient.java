package com.intelse.attack;

import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkClient {
    public String sendAttack(String targetIp) throws Exception {
        // Mock HTTP POST request for demonstration
        try {
            URL url = new URL("http://" + targetIp);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.connect();
            int responseCode = conn.getResponseCode();
            return "Attack sent to " + targetIp + ", response code: " + responseCode;
        } catch (Exception e) {
            throw new Exception("Network error: " + e.getMessage());
        }
    }
}
