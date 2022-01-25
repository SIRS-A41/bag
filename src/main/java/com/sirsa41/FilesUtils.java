package com.sirsa41;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.utils.IOUtils;

class FilesUtils {
    private static final int BUFFER_SIZE = 1024;

    // tar.gz few files
    public static void compressTarGz(ArrayList<String> paths, String outputPath)
            throws IOException {

        Path output = Paths.get(outputPath);
        OutputStream fOut;
        BufferedOutputStream bOut;
        GzipCompressorOutputStream gzOut;
        TarArchiveOutputStream tOut;

        fOut = Files.newOutputStream(output);
        bOut = new BufferedOutputStream(fOut);
        gzOut = new GzipCompressorOutputStream(bOut);
        tOut = new TarArchiveOutputStream(gzOut);

        for (String path : paths) {
            addFileToTarGz(tOut, path, "");
        }

        tOut.finish();
        tOut.close();
        gzOut.close();
        bOut.close();
        fOut.close();

    }

    static private void addFileToTarGz(TarArchiveOutputStream tOut, String path, String base)
            throws IOException {
        File f = new File(path);
        String entryName = base + f.getName();
        TarArchiveEntry tarEntry = new TarArchiveEntry(f, entryName);
        tOut.putArchiveEntry(tarEntry);

        if (f.isFile()) {
            IOUtils.copy(new FileInputStream(f), tOut);
            tOut.closeArchiveEntry();
        } else {
            tOut.closeArchiveEntry();
            File[] children = f.listFiles();
            if (children != null) {
                for (File child : children) {
                    addFileToTarGz(tOut, child.getAbsolutePath(), entryName + "/");
                }
            }
        }
    }

    static public Path writeFile(String path, byte[] bytes) {
        try {
            return Files.write(Paths.get(path), bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    static public File decompressTarGz(String tarGz, String targetDir) throws IOException {
        Files.createDirectories(Paths.get(targetDir));
        try (InputStream fi = Files.newInputStream(Paths.get(tarGz));
                BufferedInputStream bi = new BufferedInputStream(fi);
                GzipCompressorInputStream gzi = new GzipCompressorInputStream(bi);
                TarArchiveInputStream ti = new TarArchiveInputStream(gzi)) {

            ArchiveEntry entry;
            while ((entry = (TarArchiveEntry) ti.getNextEntry()) != null) {
                /** If the entry is a directory, create the directory. **/
                String newPath = Paths.get(targetDir, entry.getName()).toString();
                if (entry.isDirectory()) {
                    File f = new File(newPath);
                    if (!f.exists()) {
                        Boolean created = f.mkdirs();
                        if (!created) {
                            System.out.printf(
                                    "Unable to create directory '%s', during extraction of archive contents.\n",
                                    f.getAbsolutePath());
                        }
                    }
                } else {
                    int count;
                    byte data[] = new byte[BUFFER_SIZE];
                    FileOutputStream fos = new FileOutputStream(newPath, false);
                    try (BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER_SIZE)) {
                        while ((count = ti.read(data, 0, BUFFER_SIZE)) != -1) {
                            dest.write(data, 0, count);
                        }
                        final File file = new File(newPath);
                        file.setLastModified(entry.getLastModifiedDate().getTime());
                    }
                }
            }
            return new File(targetDir);
        }
    }

    static public void moveFiles(String sourcePath, String destPath) {
        ArrayList<String> filepaths = ls(sourcePath);
        for (String filepath : filepaths) {
            try {
                Files.move(Paths.get(sourcePath, filepath), Paths.get(destPath, filepath),
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                System.out.println(e);
                System.out.println("Failed to move " + filepath);
            }
        }
    }

    static public String cwd() {
        return System.getProperty("user.dir").toString();
    }

    static public ArrayList<String> ls(String path) {
        File directoryPath = new File(path);
        // List of all files and directories
        String contents[] = directoryPath.list();

        ArrayList<String> filteredList = new ArrayList<String>();
        for (String filepath : contents) {
            if (!filepath.equals(".bag")) {
                filteredList.add(filepath);
            }
        }
        return filteredList;
    }

    static private ArrayList<String> getFileNames(ArrayList<String> fileNames, Path dir) {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path path : stream) {
                if (path.toFile().isDirectory()) {
                    getFileNames(fileNames, path);
                } else {
                    fileNames.add(path.toAbsolutePath().toString());
                    System.out.println(path.getFileName());
                }
            }
        } catch (IOException e) {
            // do nothing
        }
        return fileNames;
    }

    static public ArrayList<String> lsRecursive(String dir) {
        final ArrayList<String> filenames = new ArrayList<String>();
        return getFileNames(filenames, Paths.get(dir));
    }
}