package tor.examples;

import org.bouncycastle.util.encoders.Base64;
import tor.*;

import java.io.IOException;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) throws IOException  {
        byte descid[] = HiddenService.getDescId("lorpzyxqxscsmscx", null, (byte)0);
        HiddenService.findResposibleDirectories(TorSocket.getConsensus(), descid);

        // TODO Auto-generated method stub
        OnionRouter local = new OnionRouter("nas", "72B0520B03E7657C04EA244545EBEA47A7E9FB0E", "127.0.0.1", 9001, 0) {
            @Override
            public PublicKey getPubKey() throws IOException {
                return TorCrypto.asn1GetPublicKey(Base64.decode("MIGJAoGBANvJUoy6nBqrKdGoMFXEtnfQ5og0H24ZKgLlnA0rglX01TGYYvDs6ymXqbKEyP0alBqtt18+9k7FRrPBHXxlVf3sU1ulOzN6OwIX4h8StFHLMN9+yBG5tfflAedt8eZpDKn5byhC7r9aySogOTzvMdRXqQoKsFnim6saAHWLQXzRAgMBAAE="));
            }
        };

        TorSocket sock = new TorSocket(local);

        // connected---------------
        TorCircuit circ = sock.createCircuit();
        //circ.createRoute("IPredator");
        System.out.println("Create...");
        circ.createRoute("southsea0");
        circ.waitForState(TorCircuit.STATES.READY);
        circ.send(null, TorCircuit.RELAY_DROP, false, (short)0);
        circ.destroy();
//
//
// circ.destroy();
// circ.send(null, TorC);     circ.getLastHop().df_md.update("hiohtohtohtot".getBytes()); // mangle forward digest to cause circuit failure

//        circ.send(new byte[] {0}, 107, false, (short)0);

//#        System.out.println("Extending...");
//#        circ.extend(new OnionRouter("local", "6C493EC1D035322D6575A84F040687EC5D2FA241", "192.168.0.11", 9001, 0) {
//#            @Override
//#            public PublicKey getPubKey() throws IOException {
//#                return TorCrypto.asn1GetPublicKey(Base64.decode("MIGJAoGBAMTF1X28OmCN+gt7fwRiL9fI/hd3nKdAN/sBXOrDAB/A9CW/Dd2avqeX\n" +
//#                        "ZKarmW3HbVZAdTGECu39p9h6lf5NHbLR2ZSDghcP5qb9m4ZsNg+PeLwu7M5cYRnR\n" +
//#                        "GTHIh8ybRpGGtoCoL+mVF8MCNSfELCXQ9S3YTzqN/IzyrM3+lt0HAgMBAAE="));
//#            }
        //

        System.out.println("READY!!");

    }

}
