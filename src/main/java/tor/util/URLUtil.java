package tor.util;

import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.codec.DecoderException;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang.ObjectUtils;

import java.io.IOException;

/**
 * Created by twilsonb on 3/08/2014.
 */
public class URLUtil {

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

    public static Boolean DEFAULT_MODE_ENCODE = false;

    public static void main(String[] args) {

        //for (String arg : args)
        //    System.err.println(arg);

        // Encode if there are no arguments, and it's the default
        // Or if there are arguments, and it's not the default
        if ((args.length == 0) == DEFAULT_MODE_ENCODE) {

            byte[] inBytes = new byte[ENCODING_BUFFER_SIZE];

            try {
                while (System.in.read(inBytes) != -1) {

                    String outStr = URLEncode(inBytes);
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
            // Or if there are no arguments, and it's the default


            byte[] inBytes = new byte[DECODING_BUFFER_SIZE*ENCODING_EXPANSION_RATIO];

            try {
                while (System.in.read(inBytes) != -1) {

                    byte[] outBytes = URLDecode(inBytes);
                    System.out.write(outBytes);
                }
            } catch (IOException ioe) {
                System.err.println("main: URLEncode: IO Exception. Quitting..\n"
                        + "Exception: " + ioe.toString());
                return;
            }
        }
    }

    public static String URLEncode(String text) {

        try {

            byte[] textBytes = text.getBytes();
            String encodeURLtext = URLEncode(textBytes);

            return encodeURLtext;

        } catch (NullPointerException npe) {
            System.err.println("URLEncode: Failed to encode text, returning un-encoded text.\n"
                    + "Exception: " + npe.toString());
            return text;
        }

    }

    public static String URLEncode(byte[] bytes) {

        byte[] encodeURLBytes = URLCodec.encodeUrl(null, bytes);
        String encodeURLtext = StringUtils.newStringUsAscii(encodeURLBytes);

        return encodeURLtext;
    }

    public static byte[] URLDecode(String text) {

        try {
            byte[]  textBytes = text.getBytes();
            byte[] decodeURLBytes = URLDecode(textBytes);
            return decodeURLBytes;

        } catch (NullPointerException npe) {
            System.err.println("URLDecode: Failed to decode text, returning null.\n"
                    + "Exception: " + npe.toString());
            return null;
        }

    }

    public static byte[] URLDecode(byte[] bytes) {

        try {
            byte[] decodeURLBytes = URLCodec.decodeUrl(bytes);
            return decodeURLBytes;

        } catch (DecoderException de) {
            System.err.println("URLDecode: Failed to decode text, returning un-decoded bytes.\n"
                    + "Exception: " + de.toString());
            return bytes;
        }

    }
}
