package tor.util;

import java.io.IOException;

/**
 * Created by gho on 09/08/14.
 */
public class TorCircuitException extends IOException {
    public TorCircuitException(String message) {
        super(message);
    }
}
