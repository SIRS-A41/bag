package com.sirsa41;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;

import com.google.gson.*;

public class AuthRequests {

        // the IP of the Reverse Proxy machine
        private static String HOSTNAME = "https://192.168.0.254:8443/auth";

        // client_id and client_secret used for the Auth API encoded using Base64
        private static String AUTHORIZATION = "Basic QzZFNTlCMjlBRDZEODRCMEU0RUJGQjAzNkRFNzVFMUQ6VjJaMnBBdEZhYUQ3THRVaHRHYkJOQTUraUtDajFmdysybSttNlhVaDdUWT0=";

        private static final HttpClient httpClient = HttpClient.newBuilder()
                        // add a timeout of 10 seconds (can be adjusted)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

        public static HttpResponse<String> register(String username, String password)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("username", username);
                requestJson.addProperty("password", password);

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/register"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", AUTHORIZATION)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> login(String username, String password)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("username", username);
                requestJson.addProperty("password", password);

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/login"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", AUTHORIZATION)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> logout(String refreshToken)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("refresh_token", refreshToken);

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/logout"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", AUTHORIZATION)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> accessToken(String refreshToken)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("refresh_token", refreshToken);

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/accessToken"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", AUTHORIZATION)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }
}
