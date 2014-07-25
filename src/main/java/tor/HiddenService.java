package tor;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.util.encoders.Base64;
import tor.util.TorDocumentParser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.TreeMap;

/**
 * Created by gho on 25/07/14.
 */
public class HiddenService {
    // onion as base32 encoded, replica=[0,1],
    public static byte[] getDescId(String onion, byte replica) {
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

    public static OnionRouter[] findResposibleDirectories(String onionb32) {
        Consensus con = Consensus.getConsensus();

        // get list of nodes with HS dir flag
        TreeMap<String,OnionRouter> routers = con.getORsWithFlag("HSDir");
        Object keys[] = routers.keySet().toArray();
        Object vals[] = routers.values().toArray();

        ArrayList<OnionRouter> rts = new ArrayList<OnionRouter>();

        for (int replica = 0; replica < 2; replica++) {
            // Get nodes just to right of HS's descID in the DHT
            int idx = -Arrays.binarySearch(keys, Hex.encodeHexString(getDescId(onionb32, (byte) replica)));

            for (int i = 0; i < 3; i++) {
                rts.add((OnionRouter)vals[(idx+i) % vals.length]);
            }
        }

        // return list containing hopefully six ORs.
        return (OnionRouter[])rts.toArray(new OnionRouter[0]);
    }

    // blocking
    public static String fetchHSDescriptor(TorSocket sock, final String onion) throws IOException {
        // get list of ORs with resposibility for this HS
        OnionRouter ors[] = findResposibleDirectories(onion);
        // loop through responsible directories until successful
        for (int i = 0; i < ors.length; i++) {
            OnionRouter or = ors[i];
            System.out.println(or);

            // establish circuit to responsible director
            TorCircuit circ = sock.createCircuit();
            circ.create();
            circ.waitForState(TorCircuit.STATES.READY);
            circ.extend(ors[0]);
            circ.waitForState(TorCircuit.STATES.READY);

            // asynchronous call
            TorStream st = circ.createDirStream(new TorStream.TorStreamListener() {
                @Override
                public void dataArrived(TorStream s) { }

                @Override
                public void connected(TorStream s) {
                    try {
                        s.send(("GET /tor/rendezvous2/"+new Base32().encodeAsString(HiddenService.getDescId(onion, (byte) 0)).toLowerCase()+" HTTP/1.0\r\n\r\n").getBytes());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                @Override
                public void disconnected(TorStream s) { synchronized (onion) { onion.notify(); } }

                @Override
                public void failure(TorStream s) { synchronized (onion) { onion.notify(); } }
            });

            // wait for notification from the above listener that data is here! (that remote side ended connection - data could be blank
            synchronized (onion) {
                try {
                    onion.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // get HTTP response and body
            String data = new String(st.recv(4096, false));

            // HTTP success code
            if(data.length()<1 || !data.split(" ")[1].equals("200")) {
                continue;
            }

            int dataIndex = data.indexOf("\r\n\r\n");
            return new String(data.substring(dataIndex));
        }

        System.out.println("NOT FOUND HS DESCRIPTOR!!!!!!!!!!!!!1*****************");
        return null;
    }

    public static TorCircuit establishHSCircuit(TorSocket sock, String onion) throws IOException {
        String hsdescTxt = fetchHSDescriptor(sock,onion);


        // parse the hidden service descriptor
        TorDocumentParser hsdesc = new TorDocumentParser(hsdescTxt);
        //decode the intro points
        String intopointsb64 = new String(Base64.decode(hsdesc.map.get("introduction-points")));
        // parse intro points document
        TorDocumentParser intros = new TorDocumentParser(intopointsb64);
        // get first intro point
        String introPointIdentities[] = intros.getArrayItem("introduction-point");
        String ip0 = Hex.encodeHexString(new Base32().decode(introPointIdentities[0].toUpperCase()));
        System.out.println(Consensus.getConsensus().routers.get(ip0));

        return null;

    }
}
