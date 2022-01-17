package com.sirsa41;

import java.io.Console;
import java.io.IOException;
import java.net.http.HttpResponse;

import com.google.gson.*;

public class Auth {

    public static void register() {
        final String email = getInput("Enter your email: ");
        final String password = createPassword();

        System.out.println(String.format("Creating an account for user: %s...", email));

        HttpResponse<String> response;
        try {
            response = AuthRequests.register(email, password);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        }

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
        boolean firstTry = true;
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

    private static String getInput(String instructions) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        return console.readLine(instructions);
    }

    private static String getInputHidden(String instructions) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        char[] passwordArray = console.readPassword(instructions);
        return new String(passwordArray);
    }

    public static boolean isLoggedIn() {
        final String refreshToken = Config.getRefreshToken();
        return refreshToken != null;
    }

    public static void login() {
        if (isLoggedIn()) {
            final String user = Config.getUser();
            System.out.println("You are already logged in as " + user);
            return;
        }

        final String email = getInput("Enter your email: ");
        final String password = getInputHidden("Enter your password: ");
        final boolean result = actualLogin(email, password);
        if (result) {
            final String key = Resources.getPublicKey(email);
            if (key == null) {
                Resources.generateKeys();
            }
        }
        return;
    }

    private static boolean actualLogin(String email, String password) {

        HttpResponse<String> response;
        try {
            response = AuthRequests.login(email, password);
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

            try {
                Config.setUser(email);
            } catch (Exception e1) {
                e1.printStackTrace();
                System.out.println("Failed to save user: " + email);
            }

            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            final String accessToken = body.get("access_token").getAsString();
            final String refreshToken = body.get("refresh_token").getAsString();
            try {
                Config.setAccessToken(accessToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save access_token: " + accessToken);
            }
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

    // todo: logout
    public static void logout() {
        if (!isLoggedIn()) {
            System.out.println("You are not logged in");
            return;
        }

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
            Config.deleteConfig();
            System.out.println("Logout successful");
        } else {
            System.out.println("Failed to logout...");
            System.out.println(response.body());
        }
        return;
    }

    public static boolean refreshAccessToken() {
        if (!isLoggedIn()) {
            System.out.println("User not logged in");
            return false;
        }

        final String refreshToken = Config.getRefreshToken();

        HttpResponse<String> response;
        try {
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
            final String bodyRaw = response.body();
            JsonObject body = new Gson().fromJson(bodyRaw, JsonObject.class);
            final String accessToken = body.get("access_token").getAsString();
            final String newRefreshToken = body.get("refresh_token").getAsString();
            try {
                Config.setAccessToken(accessToken);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to save access_token: " + accessToken);
                return false;
            }
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