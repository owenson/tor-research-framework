package tor.util;

import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.codec.DecoderException;

import org.apache.commons.codec.binary.StringUtils;


/**
 * Created by twilsonb on 3/08/2014.
 */
public class URLUtil {

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
