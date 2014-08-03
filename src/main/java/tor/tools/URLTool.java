package tor.tools;

import sun.nio.cs.StreamDecoder;
import tor.util.URLUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;

/**
 * Created by twilsonb on 3/08/2014.
 */
public class URLTool {

    /*
     * No arguments means encode from stdin to stdout
     * Any argument(s) means decode from stdin to stdout
     *
     * This is a quick & dirty utility
     */

    // Make encoding interactive (and slow)
    // avoid accidentally adding extra null bytes to the end of the input
    public static int ENCODING_BUFFER_SIZE = 1;

    // Each encoded byte can take up to 3 ASCII characters (bytes)
    public final static int ENCODING_EXPANSION_RATIO = 3;

    public static Boolean DEFAULT_MODE_ENCODE = false;

    public static void main(String[] args) {

        //for (String arg : args)
        //    System.err.println(arg);

        // Encode if there are no arguments, and it's the default
        // (Or if there *are* arguments, and it's *not* the default)
        if ((args.length == 0) == DEFAULT_MODE_ENCODE) {

            // Use straight byte arrays to avoid corrupting input with character conversions
            // Since each byte is encoded by itself, we don't have to worry about split codes here
            byte[] inBytes = new byte[ENCODING_BUFFER_SIZE];

            try {
                while (System.in.read(inBytes) != -1) {

                    String outStr = URLUtil.URLEncode(inBytes);
                    byte[] outBytes = outStr.getBytes();
                    System.out.write(outBytes);
                }
            } catch (IOException ioe) {

                System.err.println("main: URLEncode: IO Exception. Terminating Output.\n"
                        + "Exception: " + ioe.toString());
                return;
            }

        } else {

            // Decode if there are arguments, and it's not the default
            // (Or if there are *no* arguments, and it *is* the default)

            try {
                // Buffer input to avoid decoding errors when escape sequences are split up
                // i.e. decode("%20") rather than risking decode("%") then decode("20")
                BufferedReader rdr = new BufferedReader(new InputStreamReader(System.in));

                String ln;
                while ((ln = rdr.readLine()) != null) {

                    byte[] outBytes = URLUtil.URLDecode(ln);
                    System.out.write(outBytes);
                }
            } catch (IOException ioe) {
                System.err.println("main: URLEncode: IO Exception. Terminating Output.\n"
                        + "Exception: " + ioe.toString());
                return;
            }
        }
    }
}
