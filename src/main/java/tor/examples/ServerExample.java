package tor.examples;

import tor.TorServerSocket;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

/**
 * Created by gho on 03/08/14.
 */
public class ServerExample {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateEncodingException {
        // WARNING: This example doesn't work yet :-)


        TorServerSocket serv = new TorServerSocket(9999);

    }
}
