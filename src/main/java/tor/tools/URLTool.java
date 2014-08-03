package tor.tools;

import tor.util.URLUtil;

import java.io.IOException;

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

    // Make it essentially interactive
    public static int ENCODING_BUFFER_SIZE = 1;
    public final static int ENCODING_EXPANSION_RATIO = 3;

    // try to avoid splitting codes in half
    public static int DECODING_BUFFER_SIZE = 1024;

    public static Boolean DEFAULT_MODE_ENCODE = true;

    public static void main(String[] args) {

        //for (String arg : args)
        //    System.err.println(arg);

        // Encode if there are no arguments, and it's the default
        // (Or if there *are* arguments, and it's *not* the default)
        if ((args.length == 0) == DEFAULT_MODE_ENCODE) {

            byte[] inBytes = new byte[ENCODING_BUFFER_SIZE];

            try {
                while (System.in.read(inBytes) != -1) {

                    String outStr = URLUtil.URLEncode(inBytes);
                    byte[] outBytes = outStr.getBytes();
                    System.out.write(outBytes);
                }
            } catch (IOException ioe) {

                System.err.println("main: URLEncode: IO Exception. Quitting..\n"
                        + "Exception: " + ioe.toString());
                return;
            }

        } else {

            // Decode if there are arguments, and it's not the default
            // (Or if there are *no* arguments, and it *is* the default)

            byte[] inBytes = new byte[DECODING_BUFFER_SIZE*ENCODING_EXPANSION_RATIO];

            try {
                while (System.in.read(inBytes) != -1) {

                    byte[] outBytes = URLUtil.URLDecode(inBytes);
                    System.out.write(outBytes);
                }
            } catch (IOException ioe) {
                System.err.println("main: URLEncode: IO Exception. Quitting..\n"
                        + "Exception: " + ioe.toString());
                return;
            }
        }
    }
}
