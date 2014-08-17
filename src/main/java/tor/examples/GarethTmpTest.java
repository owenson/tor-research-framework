package tor.examples;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import tor.OnionRouter;
import tor.TorCircuit;
import tor.TorCrypto;
import tor.TorSocket;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by gho on 01/08/14.
 */
public class GarethTmpTest {
    public static void main(String[] args) throws IOException {
        OnionRouter localhostOR = new OnionRouter("gholocal", "72B0520B03E7657C04EA244545EBEA47A7E9FB0E", "127.0.0.1", 9001, 0) {
            @Override
            public PublicKey getPubKey() throws IOException {
                return TorCrypto.asn1GetPublicKey(Base64.decode("MIGJAoGBAN/qGt8WCBW+5q4+04Sc1fpm1lve0HG1IMiMTWMLY6YM9QCkHOWhw8Tw\n" +
                        "4rtvsd4ZUIjx/VFHai5+DT0T2fJY2G0L6QB1Ks0kfTTqktLIXJGVQDZjxAklOllr\n" +
                        "3jt1ihRGCR84AiqfY8uWn+XUKtZYcDKQgSwpFBHWY0YIz/yJFR5NAgMBAAE="));
            }
        };

        RSAPublicKey pk = (RSAPublicKey) localhostOR.getPubKey();
        //SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(AlgorithmIdentifier.getInstance("1.2.840.113549.1.1.1"), new org.bouncycastle.asn1.pkcs.RSAPublicKey(pk.getModulus(), pk.getPublicExponent()));


        byte tmp[] = TorCrypto.publicKeyToPKCS1(pk);
        System.out.println(Hex.toHexString(tmp));
        System.out.println(Hex.toHexString(TorCrypto.getSHA1().digest(tmp)));

        byte asn1[] = TorCrypto.publicKeyToASN1(pk);
        System.out.println(Hex.toHexString(Base64.decode("MIGJAoGBAN/qGt8WCBW+5q4+04Sc1fpm1lve0HG1IMiMTWMLY6YM9QCkHOWhw8Tw\n" +
                        "4rtvsd4ZUIjx/VFHai5+DT0T2fJY2G0L6QB1Ks0kfTTqktLIXJGVQDZjxAklOllr\n" +
                        "3jt1ihRGCR84AiqfY8uWn+XUKtZYcDKQgSwpFBHWY0YIz/yJFR5NAgMBAAE=")));
        System.out.println(Hex.toHexString(asn1));
        byte digest[] = TorCrypto.getSHA1().digest(asn1);
        System.out.println(Hex.toHexString(digest));

        OnionRouter resfwserver = new OnionRouter("resfw", "1D89AC916D14C2FCF96B5173DC95F201FEE5A4D5", "127.0.0.1", 9999, 0) {
            @Override
            public PublicKey getPubKey() throws IOException {
                return TorCrypto.asn1GetPublicKey(Hex.decode("308188028180b688aa6b6222bb9dadd4e33a9176c35ca81196cbd80aec8046cbdfc92050363450bfbda3c93c086bda6e62e4f0033c041746f81ed5bc304fd501444d8f47ee249425955267689787d7997734014575b75fcb658d46beea36b82e4b28824e7f4e4ba880051cae34e0d973dc4e04edbbe392f76274d5ade909d42e3e63217b50f90203010001"));
            }
        };
        TorSocket sock = new TorSocket(localhostOR); //Consensus.getConsensus().getRandomORWithFlag("Guard,Fast"));
        TorCircuit circ = sock.createCircuit(true);
        circ.create();
        circ.extend(resfwserver);
//        String hsdsec = HiddenService.fetchHSDescriptor(sock, "3g2upl4pq6kufc4m");
//        FileWriter out = new FileWriter("duckduckgo.hsdesc");
//        out.write(hsdsec);
//        System.out.println(hsdsec);
//        TorServerSocket sock = new TorServerSocket(9001);
//        TorSocket sock = new TorSocket(new OnionRouter("local", "none", "127.0.0.1", 9001, 0));
//        Consensus con = Consensus.getConsensus();
//        TorSocket sock = new TorSocket(con.getRouterByName("Goblin500"));
//        TorCircuit circ = sock.createCircuit(true);
//        circ.create();
//        circ.extend(con.getRouterByName("CertifiedExtremist"));
    }
}
