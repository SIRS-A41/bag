package com.sirsa41;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Scanner;

public class Config {
    private static final String CONFIG_PATH = System.getProperty("user.home") + "/.config/bag/";
    private static final String ACCESS_TOKEN_PATH = CONFIG_PATH + "access_token";
    private static final String REFRESH_TOKEN_PATH = CONFIG_PATH + "refresh_token";
    private static final String USER_PATH = CONFIG_PATH + "user";
    private static final String PUBLIC_KEY_PATH = CONFIG_PATH + "public_key";
    private static final String PRIVATE_KEY_PATH = CONFIG_PATH + "private_key";

    private static void createConfigFolder() throws Exception {
        // Instantiate the File class
        File f1 = new File(CONFIG_PATH);
        // Creating a folder using mkdir() method
        boolean folderCreated = f1.mkdirs();
        if (!folderCreated) {
            throw new Exception("Failed to create folder: " + CONFIG_PATH);
        }
    }

    private static void writeToFile(String str, String filepath) throws IOException {
        File file = new File(filepath);
        file.createNewFile();
        BufferedWriter writer = new BufferedWriter(new FileWriter(filepath));
        writer.write(str);
        writer.close();
    }

    public static void setAccessToken(String accessToken) throws Exception {
        if (!fileExists(CONFIG_PATH)) {
            createConfigFolder();
        }
        writeToFile(accessToken, ACCESS_TOKEN_PATH);
    }

    public static void setRefreshToken(String refreshToken) throws Exception {
        if (!fileExists(CONFIG_PATH)) {
            createConfigFolder();
        }
        writeToFile(refreshToken, REFRESH_TOKEN_PATH);
    }

    public static void setUser(String user) throws Exception {
        if (!fileExists(CONFIG_PATH)) {
            createConfigFolder();
        }
        writeToFile(user, USER_PATH);
    }

    public static String getUser() {
        if (fileExists(USER_PATH)) {
            return readFile(USER_PATH);
        } else {
            return null;
        }
    }

    public static String getAccessToken() {
        if (fileExists(ACCESS_TOKEN_PATH)) {
            return readFile(ACCESS_TOKEN_PATH);
        } else {
            return null;
        }
    }

    public static String getRefreshToken() {
        if (fileExists(REFRESH_TOKEN_PATH)) {
            return readFile(REFRESH_TOKEN_PATH);
        } else {
            return null;
        }
    }

    public static String getPublicKey() {
        if (fileExists(PUBLIC_KEY_PATH)) {
            return readFile(PUBLIC_KEY_PATH);
        } else {
            return null;
        }
    }

    public static String getPrivateKey() {
        if (fileExists(PRIVATE_KEY_PATH)) {
            return readFile(PRIVATE_KEY_PATH);
        } else {
            return null;
        }
    }

    private static void deleteDir(File file) {
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                if (!Files.isSymbolicLink(f.toPath())) {
                    deleteDir(f);
                }
            }
        }
        file.delete();
    }

    private static void emptyDir(String filepath) {
        final File file = new File(filepath);
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                if (!Files.isSymbolicLink(f.toPath())) {
                    deleteDir(f);
                }
            }
        }
    }

    public static void setPrivateKeyFromFile(String filepath) {
        try {
            Files.copy(Paths.get(filepath), Paths.get(PRIVATE_KEY_PATH), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void deleteConfig() {
        emptyDir(CONFIG_PATH);
    }

    private static boolean fileExists(String filepath) {
        File file = new File(filepath);
        return file.exists();
    }

    // read fisrt line only
    private static String readFile(String filepath) {
        String data = null;
        try {
            File myObj = new File(filepath);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                data = myReader.nextLine();
                break;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        return data;
    }

    public static void setPrivateKey(String key) throws Exception {
        if (!fileExists(CONFIG_PATH)) {
            createConfigFolder();
        }
        writeToFile(key, PRIVATE_KEY_PATH);
    }

}
