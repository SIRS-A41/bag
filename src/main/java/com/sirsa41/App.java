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
                if (args.length < 2) {
                    System.out.println("Provide path to private_key");
                    return;
                }
                final String keyPath = args[1];
                Resources.setPrivateKey(keyPath);
            } else if (command.equals("keys")) {
                Resources.generateKeys();
            } else if (command.equals("create")) {
                if (args.length < 2) {
                    System.out.println("Provide project name");
                    return;
                }
                final String projectName = args[1];
                Resources.create(projectName);
            } else if (command.equals("clone")) {
                if (args.length < 2) {
                    System.out.println("Provide project reference");
                    return;
                }
                final String projectName = args[1];
                Resources.clone(projectName);
            } else if (command.equals("share")) {
                if (args.length < 2) {
                    System.out.println("Provide username to share with");
                    return;
                }
                final String user = args[1];
                Resources.share(user);
            } else if (command.equals("push")) {
                Resources.push();
            } else if (command.equals("projects")) {
                Resources.projects();
            } else if (command.equals("history")) {
                Resources.history();
            } else if (command.equals("pull")) {
                Resources.pull(null);
            } else if (command.equals("checkout")) {
                if (args.length < 2) {
                    System.out.println("Provide commit version");
                    return;
                }
                final String version = args[1];
                Resources.pull(version);
            } else {
                System.out.println(String.format("bag %s not implemented", command));
            }
        } else {
            System.out.println("Instructions:");
            System.out.println("bag register - Create an account");
            System.out.println("bag login - Login to account");
            System.out.println("bag user - Get current user");
            System.out.println("bag logout - Logout of your account");
            System.out.println("bag keys - Generate asymmetric key pair");
            System.out.println("bag private - Set private key");
            System.out.println("bag create <project-name> - Create a new project named <project-name>");
            System.out.println("bag clone <project-name> - Clone project named <project-name>");
            System.out.println("bag share <username> - Share project with <username>");
            System.out.println("bag history - Show project history");
            System.out.println("bag push - Push current project files to remote server");
            System.out.println("bag pull - Pull current project files from remote server");
        }
    }
}
