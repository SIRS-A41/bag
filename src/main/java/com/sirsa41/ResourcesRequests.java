package com.sirsa41;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;

import com.google.gson.*;

public class ResourcesRequests {

        private static String HOSTNAME = "http://localhost:8001/resources";

        private static final HttpClient httpClient = HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

        public static HttpResponse<String> create(String projectName)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("name", projectName);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/create"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> setPublicKey(String publicKey)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("key", publicKey);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/setPublicKey"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                return response;
        }

        public static HttpResponse<String> getPublicKey(String userId)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("user", userId);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/getPublicKey"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                return response;
        }

        public static HttpResponse<String> clone(String projectName)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("name", projectName);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/clone"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }
}
