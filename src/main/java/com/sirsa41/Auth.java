package com.sirsa41;

import java.io.Console;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.google.gson.*;

public class Auth {

    public static void register() {

        // check if user is already logged in
        if (isLoggedIn()) {
            final String user = Config.getUser();
            System.out.println("You are already logged in as " + user);
            return;
        }

        // get username
        final String username = getInput("Enter your username: ");
        // get password
        String password = createPassword();

        // derive a better and longer password using a KDF
        try {
            // the username is used as salt to avoid rainbow table attacks
            password = Encryption.deriveKey(password, username, 128);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Failed to secure password");
            return;
        }

        System.out.println(String.format("Creating an account for user: %s...", username));

        // make HTTP request
        HttpResponse<String> response;
        try {
            response = AuthRequests.register(username, password);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        }

        // check if everything went OK
        if (response.statusCode() == 200) {
            System.out.println("Account successfuly created");
        } else {
            System.out.println("Failed to register...");
            System.out.println(response.body());
        }
        return;
    }

    private static String createPassword() {
        String password = "", password2 = " ";
        Boolean firstTry = true;
        // require the user confirm the provided password
        while (!password.equals(password2)) {
            if (!firstTry) {
                System.out.println("Passwords do not match!");
            } else {
                firstTry = false;
            }
            password = getInputHidden("Enter your password: ");
            if (password.length() < 4) {
                System.out.println("Password must be at least 4 characters");
            } else {
                password2 = getInputHidden("Confirm your password: ");
            }
        }
        return password;
    }

    // method used to ask user for input
    private static String getInput(String instructions) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        return console.readLine(instructions);
    }

    // method used to ask user for input and hide it while writing
    private static String getInputHidden(String instructions) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        char[] passwordArray = console.readPassword(instructions);
        return new String(passwordArray);
    }

    // check if user is logged in by verifying if there is a refresh token
    public static Boolean isLoggedIn() {
        final String refreshToken = Config.getRefreshToken();
        return refreshToken != null;
    }

    public static void login() {
        if (isLoggedIn()) {
            final String user = Config.getUser();
            System.out.println("You are already logged in as " + user);
            return;
        }

        final String username = getInput("Enter your username: ");
        String password = getInputHidden("Enter your password: ");

        // derive improved password using KDF
        try {
            password = Encryption.deriveKey(password, username, 128);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Failed to secure password");
            return;
        }

        // make the login request
        final Boolean result = actualLogin(username, password);
        if (result) {
            // if successful, check if the user already has a public key on the
            // remote server
            final String key = Resources.getPublicKey(username);
            if (key == null) {
                // if not, generate asymmetric key pair
                Resources.generateKeys();
            } else {
                // if the user already has a public key, store it locally
                try {
                    Config.setPublicKey(key);
                } catch (Exception e) {
                    System.out.println("Failed to cache public_key");
                }
            }
        }
        return;
    }

    // login request
    private static Boolean actualLogin(String username, String password) {

        HttpResponse<String> response;
        try {
            response = AuthRequests.login(username, password);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to login");
            return false;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Failed to login");
            return false;
        }

        if (response.statusCode() == 200) {
            System.out.println("Login successful");

            // store the username of the user logged in
            try {
                Config.setUser(username);
            } catch (Exception e1) {
                e1.printStackTrace();
                System.out.println("Failed to save user: " + username);
            }

            // parse response body to Json Object
            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);

            // get access token
            final String accessToken = body.get("access_token").getAsString();

            // get refresh token
            final String refreshToken = body.get("refresh_token").getAsString();

            // store access token locally
            try {
                Config.setAccessToken(accessToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save access_token: " + accessToken);
            }

            // store refresh token locally
            try {
                Config.setRefreshToken(refreshToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save refresh_token: " + refreshToken);
            }
            return true;
        } else {
            System.out.println("Failed to login...");
            System.out.println(response.body());
        }
        return false;
    }

    public static void logout() {
        if (!isLoggedIn()) {
            System.out.println("You are not logged in");
            return;
        }

        // retrieve local refresh token
        final String refreshToken = Config.getRefreshToken();

        HttpResponse<String> response;
        try {
            response = AuthRequests.logout(refreshToken);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to logout");
            return;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Failed to logout");
            return;
        }

        if (response.statusCode() == 200) {
            // if logout was successful from the remote server, delete the local config
            // files
            Config.deleteConfig();
            System.out.println("Logout successful");
        } else {
            System.out.println("Failed to logout...");
            System.out.println(response.body());
        }
        return;
    }

    // get the current user
    public static void user() {
        if (!isLoggedIn()) {
            System.out.println("You are not logged in");
            return;
        }

        final String user = Config.getUser();

        if (user == null) {
            System.out.println("Something is wrong in your config files");
        }

        System.out.println(user);
        return;
    }

    // refresh the access token
    public static Boolean refreshAccessToken() {
        if (!isLoggedIn()) {
            System.out.println("User not logged in");
            return false;
        }

        // retrieve the refresh token from the local files
        final String refreshToken = Config.getRefreshToken();

        HttpResponse<String> response;
        try {
            // make request
            response = AuthRequests.accessToken(refreshToken);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to refresh access_token");
            return false;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Failed to refresh access_token");
            return false;
        }

        if (response.statusCode() == 200) {
            // parse response body as JSON
            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);

            // retrieve new access token
            final String accessToken = body.get("access_token").getAsString();

            // retrieve new refresh token
            final String newRefreshToken = body.get("refresh_token").getAsString();

            // store new access token locally
            try {
                Config.setAccessToken(accessToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save access_token: " + accessToken);
                return false;
            }

            // store new refresh token locally
            try {
                Config.setRefreshToken(newRefreshToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save refresh_token: " + refreshToken);
                return false;
            }
            return true;
        } else {
            System.out.println("Failed to refresh access_token...");
            System.out.println(response.body());
            return false;
        }
    }
}