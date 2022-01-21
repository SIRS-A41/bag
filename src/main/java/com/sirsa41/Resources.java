package com.sirsa41;

import java.io.File;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.ArrayList;
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
        System.out.println(String.format("Private key loaded from %s", filepath));

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

        if (Config.projectConfigFolderExists(null)) {
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
            String folderName;
            if (projectName.contains("/")) {
                folderName = projectName.split("/", 2)[1];
            } else {
                folderName = projectName;
            }
            Boolean result;
            try {
                result = Config.createProjectFolder(folderName);
            } catch (Exception e1) {
                e1.printStackTrace();
                return;
            }
            if (!result) {
                System.out.println(String.format("Folder named %s already exists", folderName));
                return;
            }

            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            final String projectId = body.get("id").getAsString();

            final String encryptedKey = body.get("key").getAsString();
            final String key = Encryption.decrypt(encryptedKey);

            try {
                Config.createProjectConfigFolder(folderName);
                Config.storeProjectId(projectId, folderName);
                Config.storeProjectKey(key, folderName);
            } catch (Exception e) {
                System.out.println("Failed to create project config folder");
            }
            System.out.println(String.format("Project %s successfuly cloned", projectName));
        } else {
            System.out.println("Failed to clone project");
            System.out.println(response.body());
        }
        return;
    }

    public static void share(String userId) {

        if (!Auth.isLoggedIn()) {
            System.out.println("You are not logged in. Login first");
            return;
        }

        if (Config.getPrivateKey() == null) {
            System.out.println("Generate an asymmetric key pair or set your private key first");
            return;
        }

        if (!Config.projectConfigFolderExists(null) || !Config.validProjectConfig()) {
            System.out.println("You are not inside a valid project folder");
            return;
        }

        final String projectId = Config.getProjectId();
        final String key = Config.getProjectKey();

        final String userKey = Resources.getPublicKey(userId);
        if (userKey == null) {
            System.out.println(String.format("Failed to retrieve public key from %s", userId));
            return;
        }
        final String encryptedKey = Encryption.encrypt(key, userKey);
        if (encryptedKey == null) {
            System.out.println(String.format("Failed to encrypt project key for %s", userId));
            return;
        }

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.share(projectId, userId, encryptedKey));
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
            System.out.println(String.format("Project successfuly shared with %s", userId));
        } else {
            System.out.println("Failed to create a project");
            System.out.println(response.body());
        }
        return;
    }

    public static void push() {
        if (!Config.projectConfigFolderExists(null) || !Config.validProjectConfig()) {
            System.out.println("You are not inside a valid project folder");
            return;
        }

        if (!Auth.isLoggedIn()) {
            System.out.println("You are not logged in. Login first");
            return;
        }

        if (Config.getPrivateKey() == null) {
            System.out.println("Generate an asymmetric key pair or set your private key first");
            return;
        }

        final String projectId = Config.getProjectId();
        final String key = Config.getProjectKey();

        final File compressed = compressProject();
        final String iv = Encryption.generateIv();
        final File encrypted = Encryption.encryptFile(compressed.getAbsolutePath(), key, iv);
        final String signature = "";

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.push(projectId, encrypted, iv, signature));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to push project files");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to push project files");
            return;
        }

        if (response.statusCode() == 200) {
            // todo
        } else {
            System.out.println("Failed to push project files");
            System.out.println(response.body());
        }
        return;
    }

    private static HttpResponse<String> makeRequest(Callable<HttpResponse<String>> request) throws Exception {
        HttpResponse<String> response = request.call();
        if (response.statusCode() == 403) {
            final Boolean success = Auth.refreshAccessToken();
            if (success) {
                response = request.call();
            }
        }
        return response;
    }

    static private File compressProject() {
        final ArrayList<String> files = ls(".");
        try {
            FilesUtils.compressTarGz(files, ".bag/compress_tmp.tar.gz");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    static private ArrayList<String> ls(String path) {
        File directoryPath = new File(path);
        // List of all files and directories
        String contents[] = directoryPath.list();

        ArrayList<String> filteredList = new ArrayList<String>();
        for (String filepath : contents) {
            if (!filepath.equals(".bag")) {
                filteredList.add(filepath);
            }
        }
        return filteredList;
    }
}