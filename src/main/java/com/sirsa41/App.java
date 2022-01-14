package com.sirsa41;

import java.io.Console;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Hello World!");
        if (args.length >= 1) {
            final String command = args[0];
            if (command.equals("register")) {
                Auth.register();
            } else if (command.equals("login")) {
                Auth.login();
            } else if (command.equals("logout")) {
                Auth.logout();
            } else if(command.equals("create")) {
                Resources.create();
            }
        }
    }
}
