package com.sirsa41;

import java.io.File;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
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
            try {
                Config.setPublicKey(publicKey);
            } catch (Exception e) {
                System.out.println("Failed to set public_key cache:");
                System.out.println(publicKey);
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
        String projectKey;
        try {
            projectKey = Encryption.generateProjectKey();
        } catch (NoSuchAlgorithmException e1) {
            System.out.println("Failed to generate project AES key");
            return;
        }
        String publicKey = Config.getPublicKey();
        String encryptedKey = Encryption.encrypt(projectKey, publicKey);

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.create(projectName, encryptedKey));
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
            final String projectId = response.body();

            try {
                Config.createProjectConfigFolder(null);

                Config.storeProjectId(projectId, null);
                Config.storeProjectKey(projectKey, null);
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
        File compressed = null;
        File encrypted = null;
        try {
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

            compressed = compressProject();
            if (compressed == null) {
                System.out.println("Failed to compress project");
                throw new Exception();
            }

            String version;
            try {
                version = Encryption.hashFile(compressed);
            } catch (NoSuchAlgorithmException | IOException e1) {
                System.out.println("Failed to hash project");
                throw new Exception();
            }
            final String versionHex = Encryption.hashToHex(version);

            HttpResponse<String> response;
            try {
                response = makeRequest(() -> ResourcesRequests.hasCommit(projectId, versionHex));
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to check latest commit version");
                throw new Exception();
            }
            boolean result;
            if (response.statusCode() == 200) {
                result = response.body().equals("true");
            } else {
                System.out.println("Failed to check latest commit version");
                throw new Exception();
            }
            if (result) {
                System.out.println(String.format("Remote server already has commit %s", versionHex));
                throw new Exception();
            }
            Config.storeProjectVersion(versionHex, null);

            final String iv = Encryption.generateIv();
            encrypted = Encryption.encryptFile(compressed.getAbsolutePath(), key, iv);

            String hash;
            try {
                hash = Encryption.hashFile(encrypted);
            } catch (NoSuchAlgorithmException | IOException e1) {
                System.out.println("Failed to hash project compressed and encrypted");
                throw new Exception();
            }

            final String privateKey = Config.getPrivateKey();
            final String signature = Encryption.signHash(hash, privateKey);

            try {
                final File _encrypted = encrypted;
                response = makeRequest(() -> ResourcesRequests.push(projectId, _encrypted, iv, signature, versionHex));
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Failed to push project files");
                throw new Exception();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to push project files");
                throw new Exception();
            }

            if (response.statusCode() == 200) {
                final String hashHexServer = response.body();
                final String hashHex = Encryption.hashToHex(hash);
                if (!hashHexServer.equals(hashHex)) {
                    System.out.println("Your local hash differs from the server hash. The server might be compromised");
                }
                System.out.println("Successful push");
                System.out.println(String.format("Commit: %s", versionHex));
            } else {
                System.out.println("Failed to push project files");
                System.out.println(response.body());
            }
        } catch (Exception e) {
            // do nothing
        } finally {
            if (encrypted != null) {
                encrypted.delete();
            }
            if (compressed != null) {
                compressed.delete();
            }
        }
        return;

    }

    public static void pull() {
        File compressed = null;
        File encrypted = null;
        try {
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
            if (projectId == null) {
                System.out.println("Invalid project_id");
                throw new Exception();
            }
            final String key = Config.getProjectKey();
            if (key == null) {
                System.out.println("Invalid project key");
                throw new Exception();
            }
            final String myVersion = Config.getProjectVersion();

            HttpResponse<String> response;
            try {
                response = makeRequest(() -> ResourcesRequests.versions(projectId));
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to check latest commit version");
                throw new Exception();
            }
            if (response.statusCode() == 200) {
                final String bodyRaw = response.body();
                final JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
                final JsonArray history = body.get("history").getAsJsonArray();
                final JsonObject commit = history.get(0).getAsJsonObject();
                final String version = commit.get("version").getAsString();
                if (version.equals(myVersion)) {
                    System.out.println("You are already on the latest commit");
                    throw new Exception();
                }
            } else {
                System.out.println("Failed to check latest commit version");
                throw new Exception();
            }

            try {
                response = makeRequest(() -> ResourcesRequests.pull(projectId));
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Failed to push project files");
                throw new Exception();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to push project files");
                throw new Exception();
            }

            if (response.statusCode() == 200) {
                // todo
            } else {
                System.out.println("Failed to push project files");
                System.out.println(response.body());
            }
        } catch (Exception e) {
            // do nothing
        } finally {
            if (encrypted != null) {
                encrypted.delete();
            }
            if (compressed != null) {
                compressed.delete();
            }
        }
        return;

    }

    public static void history() {
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
        String myVersion = Config.getProjectVersion();
        if (myVersion == null) {
            myVersion = "";
        }

        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.versions(projectId));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to retrieve project history");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to retrieve project history");
            return;
        }

        if (response.statusCode() == 200) {
            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            JsonArray history = body.get("history").getAsJsonArray();
            JsonObject commit;
            String timestamp;
            String user;
            String version;
            String indicator;
            for (int i = 0; i < history.size(); i++) {
                commit = history.get(i).getAsJsonObject();
                version = commit.get("version").getAsString();
                user = commit.get("user").getAsString();
                timestamp = parseSecondsSinceEpoch(commit.get("timestamp").getAsString());
                if (myVersion.equals(version)) {
                    indicator = ">";
                } else {
                    indicator = "-";
                }
                System.out.println(String.format("%s %s - %s - %s", indicator, timestamp, user, version));
            }
        } else {
            System.out.println("Failed to retrieve project history");
            System.out.println(response.body());
        }
        return;
    }

    static private String parseSecondsSinceEpoch(String timestamp) {
        long seconds = Integer.parseInt(timestamp) * 1;
        LocalDateTime dateTime = LocalDateTime.ofEpochSecond(seconds, 0, ZoneOffset.UTC);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm", Locale.ENGLISH);
        return dateTime.format(formatter);
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
        final String filepath = ".bag/compress_tmp.tar.gz";
        try {
            FilesUtils.compressTarGz(files, filepath);
            return new File(filepath);
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