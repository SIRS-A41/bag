package com.sirsa41;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.concurrent.Callable;

public class Resources {

    public static void setPrivateKey(String filepath) {
        if (!Auth.isLoggedIn()) {
            System.out.println("User not logged in");
            return;
        }

        if (Config.getPrivateKey() != null) {
            System.out.println("You already have a private key");
            return;
        }

        Config.setPrivateKeyFromFile(filepath);

        return;
    }

    public static void generateKeys() {
        if (!Auth.isLoggedIn()) {
            System.out.println("User not logged in");
            return;
        }

        if (Config.getPublicKey() != null) {
            System.out.println("User already has keys");
            return;
        }

        final String[] keys = Encryption.generateAsymmetricKeys();
        final String publicKey = keys[0];
        final String privateKey = keys[1];

        try {
            Config.setPrivateKey(privateKey);
        } catch (Exception e) {
            System.out.println("Failed to set private_key cache:");
            System.out.println(privateKey);
        }

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.setPublicKey(publicKey));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to set public key");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to set public key");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("SAVE your private key:");
            System.out.println(privateKey);
            System.out.println("Public key successfuly set");
        } else {
            System.out.println("Failed to set public key");
            System.out.println(response.body());
        }
        return;
    }

    public static void create(String projectName) {
        if (!Auth.isLoggedIn()) {
            System.out.println("You are not logged in. Login first");
            return;
        }

        System.out.println(String.format("Creating project: %s", projectName));

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.create(projectName));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to create a project");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to create a project");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("Project successfuly created");
        } else {
            System.out.println("Failed to create a project");
            System.out.println(response.body());
        }
        return;
    }

    private static HttpResponse<String> makeRequest(Callable<HttpResponse<String>> request) throws Exception {
        HttpResponse<String> response = request.call();
        if (response.statusCode() == 403) {
            final boolean success = Auth.refreshAccessToken();
            if (success) {
                response = request.call();
            }
        }
        return response;
    }
}