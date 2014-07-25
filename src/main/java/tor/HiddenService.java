package tor;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Created by gho on 25/07/14.
 */
public class HiddenService {
    // onion as base32 encoded, replica=[0,1],
    public static byte[] getDescId(String onion, String desc_cookie, byte replica) {
        byte[] onionbin = new Base32().decode(onion.toUpperCase());
        assert onionbin.length == 10;

        long curtime = System.currentTimeMillis()/1000L;
        int oid = onionbin[0] & 0xff;

        long t = (curtime + (oid * 86400L / 256)) / 86400L;

        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.putInt((int)t);
        buf.put(replica);
        buf.flip();

        MessageDigest md = TorCrypto.getSHA1();
        md.update(buf);
        byte hashT[] = md.digest();

        md = TorCrypto.getSHA1();
        return md.digest(ArrayUtils.addAll(onionbin, hashT)); //md.digest();
    }

    public static void findResposibleDirectories(Consensus con, byte[] descid) {
        Object keys[] = con.routers.keySet().toArray();
        Object vals[] = con.routers.values().toArray();

        int idx = -Arrays.binarySearch(keys, Hex.encodeHexString(descid));
        System.out.println(((OnionRouter)vals[idx]).identityhash);


    }
}
