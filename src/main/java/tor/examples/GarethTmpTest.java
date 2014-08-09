package tor.examples;

import tor.Consensus;
import tor.TorCircuit;
import tor.TorSocket;

import java.io.IOException;

/**
 * Created by gho on 01/08/14.
 */
public class GarethTmpTest {
    public static void main(String[] args) throws IOException {
//        OnionRouter localhostOR = new OnionRouter("gholocal", "72B0520B03E7657C04EA244545EBEA47A7E9FB0E", "127.0.0.1", 9001, 0) {
//            @Override
//            public PublicKey getPubKey() throws IOException {
//                return TorCrypto.asn1GetPublicKey(Base64.decode("MIGJAoGBANvJUoy6nBqrKdGoMFXEtnfQ5og0H24ZKgLlnA0rglX01TGYYvDs6ymX\n" +
//                        "qbKEyP0alBqtt18+9k7FRrPBHXxlVf3sU1ulOzN6OwIX4h8StFHLMN9+yBG5tffl\n" +
//                        "Aedt8eZpDKn5byhC7r9aySogOTzvMdRXqQoKsFnim6saAHWLQXzRAgMBAAE="));
//            }
//        };
//        TorSocket sock = new TorSocket(localhostOR); //Consensus.getConsensus().getRandomORWithFlag("Guard,Fast"));
//        String hsdsec = HiddenService.fetchHSDescriptor(sock, "3g2upl4pq6kufc4m");
//        FileWriter out = new FileWriter("duckduckgo.hsdesc");
//        out.write(hsdsec);
//        System.out.println(hsdsec);
        //TorServerSocket sock = new TorServerSocket(9001);
        //TorSocket sock = new TorSocket(new OnionRouter("local", "none", "127.0.0.1", 9001, 0));
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRouterByName("Goblin500"));
        TorCircuit circ = sock.createCircuit(true);
        circ.create();
        circ.extend(con.getRouterByName("CertifiedExtremist"));
    }
}
