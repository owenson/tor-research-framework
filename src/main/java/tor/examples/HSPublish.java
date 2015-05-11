package tor.examples;

import org.bouncycastle.util.encoders.Base64;
import tor.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;

/**
 * Created by gho on 02/01/15.
 */
public class HSPublish {
    public static void main(String[] args) throws IOException {
        // HS key - from shallot - also takes tor keys - or generate one
        byte[] privkey = Base64.decode("MIICXAIBAAKBgQDbIj4jIs87Xd8NwvHOYUxdtGfkn4vRPLR7k02mUqkhnx30GnS0\n" +
                "YxzdPfkJZT+hx0w4NL1XYU6dDY61eE97mqQ6NPTR9gcQad8fsRZdZYekWuulNYYp\n" +
                "Q4eWCN4M1x4TaxpjL49CgOimRm/mhniAEKi1LiPiYJvuG4hGxyk6A1WN3wIDCDwj\n" +
                "AoGAFBow5cccXrQ4vJGte+ksKyo6DVwGNjmyBWITRP1upuVwA7GlCyzFQ+X+mufu\n" +
                "2p2zGNrBgrfRQzfo1XY2YGaUqwcqDDi4Pn4Coxhfx7GGAWU6YquvhnN49dZxbazv\n" +
                "lsmyUE43yPWgoTeXBDcOkYGcPuwvMQV2dLumTDO4GkHVIGsCQQD41gSY+DdAaT2d\n" +
                "nkldk2hBY6/xu1fNUerD++/7lYV91MaoiMhx9n4UQF9fpssXat7qKpgPp/fbim7d\n" +
                "mC18DseDAkEA4XFP3Mt7s96orJAwESzXZJqeCT5LMYfq9Oif9cM96QWnlnHSfDx9\n" +
                "uTennA5YWMhHlUlYZe4wZVSYHM39sIz1dQJASKjwEl/k0MftEc5e1ldDLaJXxPL/\n" +
                "q5APGVQTg9Qdst64WJ89+SB9kbdMgu0FYDMCihq0uCILUpqD2Z84NrR+rQJAPeld\n" +
                "J/MbCReod00zF5CpI46wEyLSS8OKKmojavIaKzZP8V4xXhspqnxxhoLIRQI6J2ho\n" +
                "+DqC+bz+c02IopUJxwJBAPin58CCEVWmn09JZ9ltavYla8cUe4V9m0jWVX5jR2Cg\n" +
                "no+6yHPSVlKCkZ1DSiyFrGmYODlXSMV+7EaiAGW9z2k=");

        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(InetAddress.getLocalHost(), 9001);
        //new TorSocket(con.getRandomORWithFlag("Guard,Fast,Valid,Running".split(",")));
        String onion = HiddenService.publicKeyToOnion(TorCrypto.asn1GetPrivateKeyPublic(privkey));
        OnionRouter resp[] = HiddenService.findResposibleDirectories(onion);

        final String descriptor = HiddenService.generateHSDescriptor(privkey);

        System.out.println(descriptor);

        TorCircuit circ = sock.createCircuit(true);
        circ.create();
      //  circ.extend(resp[1]);
        TorStream st = circ.createDirStream(new TorStream.TorStreamListener() {
                    @Override
                    public void dataArrived(TorStream s) {
                        byte buf[] = new byte[4096];
                        try {
                            s.recv(buf, false);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        System.out.println(new String(buf));
                    }

                    @Override
                    public void connected(TorStream s) {
                        try {
                            s.send(("POST /tor/rendezvous2/publish HTTP/1.0\r\nContent-Length: "+descriptor.length()+"\r\n\r\n" + descriptor + "\r\n\r\n").getBytes());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    @Override
                    public void disconnected(TorStream s) {

                    }

                    @Override
                    public void failure(TorStream s) {

                    }
                });


    }
}
