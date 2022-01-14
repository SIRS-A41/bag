package com.sirsa41;

public class Config {
    public static void login() {
        // Instantiate the File class
        File f1 = new File(path);
        // Creating a folder using mkdir() method
        boolean bool = f1.mkdir();
        if (bool) {
            System.out.println("Folder is created successfully");
        } else {
            System.out.println("Error Found!");
        }
    }
}
