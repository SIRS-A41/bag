package com.sirsa41;

import java.io.File;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
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
        System.out.println("Generating user asymmetric keys...");

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

        System.out.println("Uploading public key to remote server...");
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
        System.out.println("Generating project symmetric key...");
        String projectKey;
        try {
            projectKey = Encryption.generateProjectKey();
        } catch (NoSuchAlgorithmException e1) {
            System.out.println("Failed to generate project AES key");
            return;
        }
        System.out.println("Encrypting project key...");
        String publicKey = Config.getPublicKey();
        String encryptedKey = Encryption.encrypt(projectKey, publicKey);

        System.out.println("Uploading encrypted key to server...");
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
            System.out.println("Project successfuly created!");
            System.out.println("You can now push your files to the remote server");
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

        System.out.println("Retrieving project information from remote server...");
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

            System.setProperty("user.dir", Config.projectFolderPath(folderName));
            final boolean pullResult = pull(null);
            if (!pullResult) {
                return;
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

        System.out.println(String.format("Retrieving %s public key...", userId));
        final String userKey = Resources.getPublicKey(userId);
        if (userKey == null) {
            System.out.println(String.format("Failed to retrieve public key from %s", userId));
            return;
        }
        System.out.println(String.format("Encrypting project key for %s...", userId));
        final String encryptedKey = Encryption.encrypt(key, userKey);
        if (encryptedKey == null) {
            System.out.println(String.format("Failed to encrypt project key for %s", userId));
            return;
        }

        System.out.println(String.format("Uploading new key to remote server...", userId));
        HttpResponse<String> response;
        try {
            response = makeRequest(() -> ResourcesRequests.share(projectId, userId, encryptedKey));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to share this project");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to share this project");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println(String.format("Project successfuly shared with %s", userId));
        } else {
            System.out.println("Failed to share this project");
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

            System.out.println("Compressing project files...");
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

            System.out.println("Checking local version against remote server...");
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

            System.out.println("Encrypting project files...");
            final String iv = Encryption.generateIv();
            encrypted = Encryption.encryptFile(compressed.getAbsolutePath(), key, iv);

            System.out.println("Signing commit...");
            String hash;
            try {
                hash = Encryption.hashFile(encrypted);
            } catch (NoSuchAlgorithmException | IOException e1) {
                System.out.println("Failed to hash project compressed and encrypted");
                throw new Exception();
            }

            final String privateKey = Config.getPrivateKey();
            final String signature = Encryption.signHash(hash, privateKey);

            System.out.println("Pushing project files to remote server..");
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
                    System.out.println(
                            "Your local hash differs from the hash the server received. The server might be compromised");
                }
                Config.storeProjectVersion(versionHex, null);
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

    public static boolean pull(String commitVersion) {
        File compressed = null;
        File encrypted = null;
        boolean result = false;
        try {
            if (!Config.projectConfigFolderExists(null) || !Config.validProjectConfig()) {
                System.out.println("You are not inside a valid project folder");
                return false;
            }

            if (!Auth.isLoggedIn()) {
                System.out.println("You are not logged in. Login first");
                return false;
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

            compressed = compressProject();
            if (compressed == null) {
                System.out.println("Failed to compress project");
                throw new Exception();
            }

            String myVersion;
            try {
                myVersion = Encryption.hashFile(compressed);
            } catch (NoSuchAlgorithmException | IOException e1) {
                compressed.delete();
                System.out.println("Failed to hash project");
                throw new Exception();
            }
            compressed.delete();
            final String myVersionHex = Encryption.hashToHex(myVersion);

            String version;
            if (commitVersion == null) {
                System.out.println("Checking local version against remote server...");
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
                    version = commit.get("version").getAsString();
                    if (version.equals(myVersionHex)) {
                        System.out.println("You are already on the latest commit");
                        throw new Exception();
                    }
                } else {
                    System.out.println("Failed to check latest commit version");
                    throw new Exception();
                }

                System.out.println("Pulling latest commit from remote server...");
            } else {
                if (commitVersion.equals(myVersionHex)) {
                    System.out.println("You are already on commit " + commitVersion);
                    throw new Exception();
                } else {
                    version = commitVersion;
                    System.out.println(String.format("Pulling commit %s from remote server...", version));
                }
            }
            HttpResponse<byte[]> response2;
            try {
                if (commitVersion != null) {
                    final String _version = commitVersion;
                    response2 = makeRequest2(() -> ResourcesRequests.pull(projectId, _version));
                } else {
                    response2 = makeRequest2(() -> ResourcesRequests.pull(projectId, null));
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Failed to pull project files");
                throw new Exception();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to pull project files");
                throw new Exception();
            }

            if (response2.statusCode() == 206) {
                final String signature = response2.headers().firstValue("x-signature").get();
                final String user = response2.headers().firstValue("x-user").get();
                final String iv = response2.headers().firstValue("x-iv").get();

                final String publicKey = getPublicKey(user);
                if (publicKey == null) {
                    System.out.println(String.format("Failed to retreive public key of %s", user));
                    throw new Exception();
                }

                System.out.println("Verifying file signature...");
                final byte[] file = response2.body();
                final String hash = Encryption.hashBytes(file);
                final boolean valid = Encryption.validateSignature(hash, signature, publicKey);

                if (!valid) {
                    System.out.println("Downloaded file signature is not valid. The server might be compromised");
                    System.out.println("Aborting...");
                    throw new Exception();
                }
                final String configPath = Config.projectConfigFolderPath(null);
                final Path encryptedPath = FilesUtils.writeFile(
                        Paths.get(configPath, String.format("%s.encrypted", version))
                                .toString(),
                        file);
                if (encryptedPath == null) {
                    System.out.println("Failed to save project files");
                    throw new Exception();
                }

                System.out.println("Decrypting project files...");
                encrypted = encryptedPath.toFile();
                compressed = Encryption.decryptFile(encrypted.getAbsolutePath(), key, iv);
                final String destPath = Paths.get(Config.projectFolderPath(null)).toString();

                System.out.println("Decompressing project files...");
                Config.deleteProjectFiles();
                FilesUtils.decompressTarGz(compressed.getAbsolutePath(),
                        destPath);
                Config.storeProjectVersion(version, null);

                System.out.println("Successful pull!");
                System.out.println(String.format("Commit: %s", version));
                result = true;
            } else {
                System.out.println("Failed to pull project files");
                System.out.println(new String(response2.body()));
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
        return result;

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
                    indicator = " ";
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

    private static HttpResponse<byte[]> makeRequest2(Callable<HttpResponse<byte[]>> request) throws Exception {
        HttpResponse<byte[]> response = request.call();
        if (response.statusCode() == 403) {
            final Boolean success = Auth.refreshAccessToken();
            if (success) {
                response = request.call();
            }
        }
        return response;
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
        final String cwd = System.getProperty("user.dir").toString();
        final ArrayList<String> files = FilesUtils.ls(cwd);
        final String filepath = Paths.get(cwd, ".bag/compress_tmp.tar.gz").toString();
        try {
            FilesUtils.compressTarGz(files, filepath);
            return new File(filepath);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

}