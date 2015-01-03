package tor.examples;

import org.bouncycastle.util.encoders.Base64;
import tor.*;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by gho on 01/01/15.
 */
public class HSRenzCircuit {
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.out.println("Specify target relay");
            System.exit(1);
        }
        //relay to rendezvous on
        String relay = args[0];
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRandomORWithFlag("Guard,Fast,Valid,Running".split(",")));

        // establish RP
        TorCircuit circ = sock.createCircuit(true);
        circ.create();
        circ.extend(con.getRouterByName(relay));
        circ.rendezvousSetup();

        // create another ciruit as HS and rendezvous at RP with first circuit
        TorCircuit circ2 = sock.createCircuit(true);
        circ2.create();
        circ2.extend(con.getRouterByName(relay));
        circ2.rendezvous2Setup(circ.rendezvousCookie);

        circ.waitForState(TorCircuit.STATES.RENDEZVOUS_COMPLETE,true);

        // add HS crypto key otherwise it becomes recognised on RP and dropped
        // ideally you'd set keys up properly here
        circ2.hops.add(new TorHop(new byte[100], new byte[100], null)); //otherwise becomes recognised on target relay and it wont fwd

        // send packets down the circuit and they should come back on circ and vice versus
        while(true) {
            circ2.send(new byte[100], TorCircuit.RELAY_DROP, false, (byte)0);
        }

    }
}
