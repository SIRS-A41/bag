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

        public static HttpResponse<String> create(String projectName, String accessToken)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("name", projectName);

                HttpRequest request = HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .uri(URI.create(HOSTNAME + "/create"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader(
                                                "Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

}
