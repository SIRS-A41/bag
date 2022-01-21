package com.sirsa41;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

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

    static public void decompressTarGz(String tarGz, String targetDir) throws IOException {
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
                    }
                }
            }
        }
    }

}