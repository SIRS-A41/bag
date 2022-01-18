package com.sirsa41;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) {
        if (args.length >= 1) {
            final String command = args[0];
            if (command.equals("register")) {
                Auth.register();
            } else if (command.equals("login")) {
                Auth.login();
            } else if (command.equals("user")) {
                Auth.user();
            } else if (command.equals("logout")) {
                Auth.logout();
            } else if (command.equals("private")) {
                final String keyPath = args[1];
                Resources.setPrivateKey(keyPath);
            } else if (command.equals("keys")) {
                Resources.generateKeys();
            } else if (command.equals("create")) {
                final String projectName = args[1];
                Resources.create(projectName);
            } else if (command.equals("clone")) {
                final String projectName = args[1];
                Resources.clone(projectName);
            } else if (command.equals("share")) {
                final String user = args[1];
                Resources.share(user);
            } else {
                System.out.println(String.format("bag %s not implemented", command));
            }
        } else {
            System.out.println("Instructions:");
            System.out.println("bag register - Create an account");
            System.out.println("bag login - Login to account");
            System.out.println("bag logout - Logout of your account");
            System.out.println("bag keys - Generate asymmetric key pair");
            System.out.println("bag private - Set private key");
            System.out.println("bag create <project-name> - Create a new project named <project-name>");
        }
    }
}
