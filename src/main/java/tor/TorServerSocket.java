package tor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tor.util.TrustAllManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by gho on 03/08/14.
 */
public class TorServerSocket extends TorSocket {
    /**
     * Sets up port listener
     *
     * @param localPort
     * @throws IOException
     */
    public TorServerSocket(int localPort) throws IOException {

        Security.addProvider(new BouncyCastleProvider());
        SSLContext sc;

        try {
            sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[] { new TrustAllManager() }, new java.security.SecureRandom());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // connect
        ServerSocket listenSocket = sc.getServerSocketFactory().createServerSocket(localPort);

        while(true) {
            Socket client = listenSocket.accept();
            System.out.println("New client connection from "+client.getRemoteSocketAddress());

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
        in = client.getInputStream();
        out = client.getOutputStream();

        new Thread(new Runnable() {
            @Override
            public void run() {
                receiveHandlerLoop();
            }
        }).start();
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
                        System.out.println("Negotiated protocol version: " + PROTOCOL_VERSION);
                        sendNetInfo();
                        continue;

                    case Cell.CREATED:
                        System.out.println("Got created cell - not impl!");
                        continue;

                    default:
                        System.out.println("[UNHANDLED] Got cell cmd "+c.cmdId);
                        continue;
                }
            } catch (IOException e) {
                System.out.println("Closing tor client connection: " + e);
                break;
            }
        }
    }
}
