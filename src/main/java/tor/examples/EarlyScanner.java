package tor.examples;

import tor.Consensus;
import tor.HiddenService;
import tor.TorSocket;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * Created by gho on 09/08/14.
 */
public class EarlyScanner {
    public static void main(String[] args) throws IOException {
        Consensus con = Consensus.getConsensus();
        con.setUseOnlyAuthorities(true);
        con.fetchAllDescriptors();
        TorSocket sock = new TorSocket(con.getRandomORWithFlag("Guard,Fast,Valid,Running"));

        // NOTE: TorCircuit.handleReceived throws exception on PADDING/EARLY/DROP cells which can be indicative of
        // deanon attack
        // this loop fetches hidden service descriptors for all known onions - a HSDir wishing to deanno a client can
        // inject these packets

        BufferedReader in = new BufferedReader(new FileReader(new File("/home/gho/onionslist")));
        String onionb32;
        while((onionb32 = in.readLine())!=null) {
            System.out.println("!!!!!!!!!!: "+onionb32);
            HiddenService.fetchHSDescriptor(sock, onionb32);
        }
    }

}
