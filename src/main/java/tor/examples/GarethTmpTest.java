package tor.examples;

import org.bouncycastle.util.encoders.Base64;
import tor.HiddenService;
import tor.OnionRouter;
import tor.TorCrypto;
import tor.TorSocket;

import java.io.FileWriter;
import java.io.IOException;
import java.security.PublicKey;

/**
 * Created by gho on 01/08/14.
 */
public class GarethTmpTest {
    public static void main(String[] args) throws IOException {
        OnionRouter localhostOR = new OnionRouter("gholocal", "72B0520B03E7657C04EA244545EBEA47A7E9FB0E", "127.0.0.1", 9001, 0) {
            @Override
            public PublicKey getPubKey() throws IOException {
                return TorCrypto.asn1GetPublicKey(Base64.decode("MIGJAoGBANvJUoy6nBqrKdGoMFXEtnfQ5og0H24ZKgLlnA0rglX01TGYYvDs6ymX\n" +
                        "qbKEyP0alBqtt18+9k7FRrPBHXxlVf3sU1ulOzN6OwIX4h8StFHLMN9+yBG5tffl\n" +
                        "Aedt8eZpDKn5byhC7r9aySogOTzvMdRXqQoKsFnim6saAHWLQXzRAgMBAAE="));
            }
        };
        TorSocket sock = new TorSocket(localhostOR); //Consensus.getConsensus().getRandomORWithFlag("Guard,Fast"));
        String hsdsec = HiddenService.fetchHSDescriptor(sock, "3g2upl4pq6kufc4m");
        FileWriter out = new FileWriter("duckduckgo.hsdesc");
        out.write(hsdsec);
        System.out.println(hsdsec);
    }
}
