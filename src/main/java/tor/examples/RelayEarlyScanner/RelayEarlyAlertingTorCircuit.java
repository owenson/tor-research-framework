package tor.examples.RelayEarlyScanner;

import tor.Cell;
import tor.TorCircuit;
import tor.TorSocket;

import java.io.IOException;

/**
 * Used to override TorCircuit to alert and terminate on encountering a RELAY_EARLY
 */
public class RelayEarlyAlertingTorCircuit extends TorCircuit{
    public RelayEarlyAlertingTorCircuit(TorSocket sock) {
        super(sock);
    }

    @Override
    public boolean handleCell(Cell c) throws IOException {
        if(c.cmdId == Cell.RELAY_EARLY) {
            System.out.println("Relay EARLY detected from "+getLastHop());
            System.exit(1);
        }
        return super.handleCell(c);
    }
}
