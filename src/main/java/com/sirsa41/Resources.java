package com.sirsa41;

import java.io.Console;
import java.io.IOException;
import java.net.http.HttpResponse;

public class Resources {

    public static void create() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        final String projectName = console.readLine("Project name: ");

        System.out.println(String.format("Creating project: %s...", projectName));

        final String accessToken = "example";

        HttpResponse<String> response;
        try {
            response = ResourcesRequests.create(projectName, accessToken);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to create a project");
            return;
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            System.out.println("Failed to create a project");
            return;
        }

        if (response.statusCode() == 200) {
            System.out.println("Project successfuly created");
        } else if (response.statusCode() == 403) {
            // todo: renew token
            System.out.println(response.body());
        } else {
            System.out.println(response.body());
        }
        return;
    }
}