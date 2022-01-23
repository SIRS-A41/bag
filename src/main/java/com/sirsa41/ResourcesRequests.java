package com.sirsa41;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import com.google.gson.*;

public class ResourcesRequests {

        private static String HOSTNAME = "http://localhost:8001/resources";

        private static final HttpClient httpClient = HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

        public static HttpResponse<String> create(String projectName, String encryptedKey)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("name", projectName);
                requestJson.addProperty("key", encryptedKey);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/create"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
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
                                .uri(URI.create(HOSTNAME + "/setPublicKey"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
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
                                .uri(URI.create(HOSTNAME + "/getPublicKey"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
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
                                .uri(URI.create(HOSTNAME + "/clone"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<byte[]> pull(String projectId)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("project", projectId);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/pull"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

                return response;
        }

        public static HttpResponse<String> share(String projectId, String userId, String encryptedKey)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("project", projectId);
                requestJson.addProperty("user", userId);
                requestJson.addProperty("key", encryptedKey);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/share"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> hasCommit(String projectId, String hash)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("project", projectId);
                requestJson.addProperty("version", hash);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/hasCommit"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> versions(String projectId)
                        throws IOException, InterruptedException {
                JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
                requestJson.addProperty("project", projectId);

                final String accessToken = Config.getAccessToken();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/versions"))
                                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static HttpResponse<String> push(String projectId, File encryptedProject, String iv, String signature,
                        String version)
                        throws IOException, InterruptedException {

                final String accessToken = Config.getAccessToken();

                Map<Object, Object> data = new HashMap<>();
                // fields
                data.put("project", projectId);
                data.put("iv", iv);
                data.put("signature", signature);
                data.put("version", version);

                // file upload
                data.put("file", encryptedProject.toPath());

                // Random 256 length string is used as multipart boundary
                String boundary = new BigInteger(256, new Random()).toString();

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(HOSTNAME + "/push"))
                                .setHeader("User-Agent", "Java 11 HttpClient Bag")
                                .setHeader("Authorization", "Bearer " + accessToken)
                                .headers("Content-Type",
                                                "multipart/form-data; boundary=" + boundary)
                                .POST(ofMimeMultipartData(data, boundary))
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                return response;
        }

        public static BodyPublisher ofMimeMultipartData(Map<Object, Object> data,
                        String boundary) throws IOException {
                ArrayList<byte[]> byteArrays = new ArrayList<byte[]>();
                byte[] separator = ("--" + boundary
                                + "\r\nContent-Disposition: form-data; name=")
                                                .getBytes(StandardCharsets.UTF_8);
                for (Map.Entry<Object, Object> entry : data.entrySet()) {
                        byteArrays.add(separator);

                        if (entry.getValue() instanceof Path) {
                                Path path = (Path) entry.getValue();
                                String mimeType = Files.probeContentType(path);
                                if (mimeType == null) {
                                        mimeType = "application/octet-stream";
                                }
                                byteArrays.add(("\"" + entry.getKey() + "\"; filename=\""
                                                + path.getFileName() + "\"\r\nContent-Type: " + mimeType
                                                + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
                                byteArrays.add(Files.readAllBytes(path));
                                byteArrays.add("\r\n".getBytes(StandardCharsets.UTF_8));
                        } else {
                                byteArrays.add(
                                                ("\"" + entry.getKey() + "\"\r\n\r\n" + entry.getValue()
                                                                + "\r\n").getBytes(StandardCharsets.UTF_8));
                        }
                }
                byteArrays
                                .add(("--" + boundary + "--").getBytes(StandardCharsets.UTF_8));
                return BodyPublishers.ofByteArrays(byteArrays);
        }

}
