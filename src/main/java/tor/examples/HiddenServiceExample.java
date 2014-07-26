package tor.examples;

import tor.*;

import java.io.IOException;

public class HiddenServiceExample {

    public static void main(String[] args) throws IOException  {
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRouterByName("turtles"));

        // setup rendezvous circuit
        TorCircuit rendz = sock.createCircuit(true); //true means circuit calls should block until success
        rendz.createRoute("tor26");
        rendz.rendezvousSetup();

        final String ONION = "3g2upl4pq6kufc4m";

        // send introduce to introduction point and wait for rendezvous circuit to complete
        HiddenService.sendIntroduce(sock, ONION, rendz);

        // Connect to hidden service on port 80 and download a page
        rendz.createStream("", 80, new TorStream.TorStreamListener() {
            @Override
            public void dataArrived(TorStream s) {
                try {
                    System.out.println(new String(s.recv(1024, false)));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void connected(TorStream s) {
                try {
                    s.sendHTTPGETRequest("/", ONION+".onion");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override public void disconnected(TorStream s) {  }
            @Override public void failure(TorStream s) {  }
        });

        System.out.println("HS - fetching index.html...");

    }

}
