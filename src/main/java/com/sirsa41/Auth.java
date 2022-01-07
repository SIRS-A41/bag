package com.sirsa41;

import java.io.Console;
import java.io.IOException;
import java.net.http.HttpResponse;

public class Auth {

    public static void register() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        final String email = console.readLine("Enter your email: ");

        String password = "", password2 = " ";
        char[] passwordArray;
        boolean firstTry = true;
        while (!password.equals(password2)) {
            if (!firstTry) {
                System.out.println("Passwords do not match!");
            } else {
                firstTry = false;
            }
            passwordArray = console.readPassword("Enter your password: ");
            if (passwordArray.length < 4) {
                System.out.println("Password must be at least 4 characters");
            } else {
                password = new String(passwordArray);
                passwordArray = console.readPassword("Confirm your password: ");
                password2 = new String(passwordArray);
            }
        }

        System.out.println(String.format("Creating an account for user: %s...", email));

        HttpResponse<String> response;
        try {
            response = AuthRequests.register(email, password);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to create an account");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("Account successfuly created");
        } else {
            System.out.println(response.body());
        }
        return;

    }

    public static void login() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        final String email = console.readLine("Enter your email: ");

        char[] passwordArray = console.readPassword("Enter your password: ");
        final String password = new String(passwordArray);

        HttpResponse<String> response;
        try {
            response = AuthRequests.login(email, password);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to login");
            return;
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to login");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("Login successful");
        }
        System.out.println(response.body());
        return;
    }

    public static void logout() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        final String email = console.readLine("Enter your email: ");

        char[] passwordArray = console.readPassword("Enter your password: ");
        final String password = new String(passwordArray);

        HttpResponse<String> response;
        try {
            response = AuthRequests.logout();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to logout");
            return;
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to logout");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("Logout successful");
        } else {
            System.out.println("Failed to logout");
        }
        return;
    }
}