package com.sirsa41;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.concurrent.Callable;

import com.google.gson.*;

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

    public static String getPublicKey(String userId) {
        if (!Auth.isLoggedIn()) {
            System.out.println("User not logged in");
            return null;
        }

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.getPublicKey(userId));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to get public key");
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to get public key");
            return null;
        }

        if (response.statusCode() == 200) {
            final String key = response.body();
            if (key.equals(""))
                return null;
            return key;
        } else {
            System.out.println("Failed to get public key");
            System.out.println(response.body());
        }
        return null;
    }

    public static void generateKeys() {
        System.out.println("Generating user asymmetric keys");

        if (!Auth.isLoggedIn()) {
            System.out.println("User not logged in");
            return;
        }

        if (Config.getPrivateKey() != null) {
            System.out.println("Key generation failed...");
            System.out.println("User already has keys");
            return;
        }

        final String[] keys = Encryption.generateAsymmetricKeys();
        final String publicKey = keys[0];
        final String privateKey = keys[1];

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
            System.out.println("Public key successfuly set");

            System.out.println("SAVE your private key:");
            System.out.println(privateKey);

            try {
                Config.setPrivateKey(privateKey);
            } catch (Exception e) {
                System.out.println("Failed to set private_key cache:");
                System.out.println(privateKey);
            }
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

        if (Config.getPrivateKey() == null) {
            System.out.println("Generate an asymmetric key pair or set your private key first");
            return;
        }

        if (Config.projectConfigFolderExists()) {
            System.out.println("Project already created");
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
            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            final String projectId = body.get("id").getAsString();

            final String encryptedKey = body.get("key").getAsString();
            final String key = Encryption.decrypt(encryptedKey);
            try {
                Config.createProjectConfigFolder(null);

                Config.storeProjectId(projectId, null);
                Config.storeProjectKey(key, null);
            } catch (Exception e) {
                System.out.println("Failed to create project config folder");
            }
            System.out.println("Project successfuly created");
        } else {
            System.out.println("Failed to create a project");
            System.out.println(response.body());
        }
        return;
    }

    public static void clone(String projectName) {
        if (!Auth.isLoggedIn()) {
            System.out.println("You are not logged in. Login first");
            return;
        }

        if (Config.getPrivateKey() == null) {
            System.out.println("Generate an asymmetric key pair or set your private key first");
            return;
        }

        System.out.println(String.format("Cloning project: %s", projectName));

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.clone(projectName));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to clone project");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to clone project");
            return;
        }

        if (response.statusCode() == 200) {
            boolean result;
            try {
                result = Config.createProjectFolder(projectName);
            } catch (Exception e1) {
                e1.printStackTrace();
                return;
            }
            if (!result) {
                System.out.println(String.format("Folder named %s already exists", projectName));
                return;
            }

            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            final String projectId = body.get("id").getAsString();

            final String encryptedKey = body.get("key").getAsString();
            final String key = Encryption.decrypt(encryptedKey);

            Config.setCurrentDirectory(String.format("./%s", projectName));
            try {
                Config.createProjectConfigFolder(projectName);
                Config.storeProjectId(projectId, projectName);
                Config.storeProjectKey(key, projectName);
            } catch (Exception e) {
                System.out.println("Failed to create project config folder");
            }
            Config.setCurrentDirectory("./..");
            System.out.println(String.format("%s successfuly cloned", projectName));
        } else {
            System.out.println("Failed to clone project");
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