package tor.examples;

import tor.Consensus;
import tor.TorCircuit;
import tor.TorSocket;
import tor.TorStream;

import java.io.IOException;

/**
 * Created by gho on 26/07/14.
 */
public class SimpleExample {
    public static void main(String[] args) throws IOException {
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRouterByName("turtles"));
        TorCircuit circ = sock.createCircuit(true);
        circ.createRoute("Snowden4ever,TorLand1");
        //circ.waitForState(TorCircuit.STATES.READY);

        TorStream stream = circ.createStream("slashdot.org", 80, null);
        stream.waitForState(TorStream.STATES.READY);
        stream.sendHTTPGETRequest("/", "slashdot.org");
        stream.waitForState(TorStream.STATES.DESTROYED);
        System.out.println(">>>" + new String(stream.recv(1024,true)));

    }
}
