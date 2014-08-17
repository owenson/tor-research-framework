package tor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by gho on 03/08/14.
 */
public class TorServerSocket extends TorSocket {
    final static Logger log = LogManager.getLogger();
    static X509Certificate identityCert;
    static RSAPublicKey identityPubKey;
    static RSAPrivateKey identityPrivKey;
    static X509Certificate linkCert;
    static X509Certificate authCert;

    /**
     * Sets up port listener
     *
     * @param localPort
     * @throws IOException
     */
    public TorServerSocket(int localPort) throws IOException, NoSuchAlgorithmException, CertificateEncodingException {

        Security.addProvider(new BouncyCastleProvider());
        SSLContext sc;

        if (!new File("keys/keystore.jks").exists()) {
            log.fatal("keys/keystore.jks not found.  Make sure you run certgen.sh in keys/");
            System.exit(1);
        }

        System.setProperty("javax.net.ssl.keyStore", "keys/keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456");
//149A17B774002FEB90048779432B0828B29EA213 but got ============ CF35FF36FAB07773D147F481EB72AD2C3209AB57
        loadKeys();

        // connect
        ServerSocket listenSocket = SSLServerSocketFactory.getDefault().createServerSocket(localPort);

        while (true) {
            Socket client = listenSocket.accept();
            System.out.println("New client connection from " + client.getRemoteSocketAddress());

            new TorServerSocket(client);

        }
    }

    /**
     * Called for each new client connection - instantiating a new object
     *
     * @param client
     * @throws IOException
     */
    private TorServerSocket(final Socket client) throws IOException {
        this.sslsocket = (javax.net.ssl.SSLSocket) client;
        in = client.getInputStream();
        out = client.getOutputStream();

        new Thread(new Runnable() {
            @Override
            public void run() {
                receiveHandlerLoop();
            }
        }).start();
    }

    public void loadKeys() {
        try {
            FileInputStream idCertIS = new FileInputStream(new File("keys/identity.crt"));
            FileInputStream linkCertIS = new FileInputStream(new File("keys/link.crt"));
            FileInputStream authCertIS = new FileInputStream(new File("keys/auth.crt"));
            CertificateFactory cf = null;
            cf = CertificateFactory.getInstance("X.509");
            identityCert = (X509Certificate) cf.generateCertificate(idCertIS);
            log.info("Our Identity Cert Digest: " + Hex.toHexString(TorCrypto.getSHA1().digest(TorCrypto.publicKeyToASN1((RSAPublicKey) identityCert.getPublicKey()))));
            linkCert = (X509Certificate) cf.generateCertificate(linkCertIS);
            log.info("Our Link Cert Digest: " + Hex.toHexString(TorCrypto.getSHA1().digest(TorCrypto.publicKeyToASN1((RSAPublicKey) linkCert.getPublicKey()))));
            authCert = (X509Certificate) cf.generateCertificate(authCertIS);
            log.info("Our Auth Cert Digest: " + Hex.toHexString(TorCrypto.getSHA1().digest(TorCrypto.publicKeyToASN1((RSAPublicKey) authCert.getPublicKey()))));
            identityPubKey = (RSAPublicKey) identityCert.getPublicKey();

            FileReader in = new FileReader("keys/identity.key");
            identityPrivKey = RSAPrivateKey.getInstance(new PemReader(in).readPemObject().getContent());
        } catch (CertificateException | IOException e) {
            log.error("Unable to load server public key");
            System.exit(1);
        }
    }

    public void sendCertsCell() throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(4096);
        buf.put((byte) 3);

        byte[] link;
        byte[] ident, auth;
        try {
            link = linkCert.getEncoded();
            ident = identityCert.getEncoded();
            auth = authCert.getEncoded();
        } catch (CertificateEncodingException e) {
            log.fatal(e);
            System.exit(1);
            return;
        }

        // LINK CERTIFICATE
        buf.put((byte)1);
        buf.putShort((short) link.length);
        buf.put(link);

        // IDENTITY CERTIFICATE
        buf.put((byte) 2);
        buf.putShort((short) ident.length);
        buf.put(ident);

        // AUTH CERTIFICATE
        buf.put((byte) 3);
        buf.putShort((short) auth.length);
        buf.put(auth);

        buf.flip();
        byte certsCell[] = new byte[buf.limit()];
        buf.get(certsCell);
        sendCell(0, Cell.CERTS, certsCell);
    }

    public void receiveHandlerLoop() {
        while(true) {
            try {
                Cell c = recvCell();
                switch (c.cmdId) {
                    case Cell.VERSIONS:
                        sendCell(0, Cell.VERSIONS, new byte[]{00, 03, 00, 04});
                        ByteBuffer verBuf = ByteBuffer.wrap(c.payload);
                        for (int i = 0; i < c.payload.length; i+=2) {
                            int offeredVer = verBuf.getShort();
                            if(offeredVer <= PROTOCOL_VERSION_MAX && offeredVer > PROTOCOL_VERSION)
                                PROTOCOL_VERSION = offeredVer;
                        }
                        log.info("Negotiated protocol version: " + PROTOCOL_VERSION);
                        sendCertsCell();
                        sendNetInfo();
                        continue;

                    case Cell.CREATED:
                        log.error("Got created cell - not impl!");
                        continue;

                    default:
                        log.info("[UNHANDLED] Got cell cmd " + c.cmdId);
                        continue;
                }
            } catch (IOException e) {
                log.error("Closing tor client connection: " + e);
                break;
            }
        }
    }
}
