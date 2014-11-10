package tor.examples;

import tor.util.TorDocumentParser;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Created by gho on 10/11/14.
 *
 * Takes a directory containing hidden service descriptors as cmd line argument (1 or more)
 * prints "Authenticated" for every descriptor which is encrypted.
 *
 * Use with 'wc -l' to print out a number
 */
public class HSIsAuthed {
    public static void main(String[] args) throws IOException {
        for (String dir : args) {
            for (File f : new File(dir).listFiles()) {
                String fd = new String(Files.readAllBytes(Paths.get(f.getAbsolutePath())));
                String ipts = new TorDocumentParser(fd).getItem("introduction-points");
                if (ipts != null && !ipts.startsWith("aW50cm9kdWN0")) {
                    System.out.println("Authenticated");
                }


            }
        }
    }
}
