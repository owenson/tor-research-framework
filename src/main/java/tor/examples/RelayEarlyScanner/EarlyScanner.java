package tor.examples.RelayEarlyScanner;

import org.apache.commons.io.FileUtils;
import tor.Consensus;
import tor.HiddenService;
import tor.TorCrypto;
import tor.TorSocket;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Created by gho on 09/08/14.
 */
public class EarlyScanner {
    public static void main(String[] args) throws IOException {
        Consensus con = Consensus.getConsensus();
        con.setUseOnlyAuthorities(true);
        con.fetchAllDescriptors();
        TorSocket sock = new TorSocket(con.getRandomORWithFlag("Guard,Fast,Valid,Running"));
        // use our RELAY_EARLY alerting TorCircuit
        sock.defaultTorCircuitClass = RelayEarlyAlertingTorCircuit.class;

        // this loop fetches hidden service descriptors for all known onions - a HSDir wishing to deanno a client can
        // inject these packets

        List<String> onions = FileUtils.readLines(new File("/home/gho/onionslist"), "UTF-8");

        // loop through onions at random
        while(true) {
            String curOnion = onions.get(TorCrypto.rnd.nextInt(onions.size())); // random onion
            System.out.println("Trying: " + curOnion);
            HiddenService.fetchHSDescriptor(sock, curOnion);
        }
    }

}
