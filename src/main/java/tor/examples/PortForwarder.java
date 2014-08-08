package tor.examples;

import tor.Consensus;
import tor.TorCircuit;
import tor.TorSocket;
import tor.TorStream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/**
 * Created by gho on 08/08/14.
 */
public class PortForwarder {
    static HashMap<SocketChannel,PortFwdClient> clients = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if(args.length != 3) {
            System.out.println("Usage: PortForwader listenPort remoteHost remotePort");
            System.out.println();
            System.out.println("If remoteHost is DIR then will establish connection to dir port on final router");
            System.out.println();
            return;
        }
        int LISTENPORT = Integer.parseInt(args[0]);
        String REMOTE=args[1];
        int PORT = Integer.parseInt(args[2]);

        System.out.println("Connection to "+REMOTE+":"+PORT+ " when client connects on localhost:"+LISTENPORT);

        // establish a circuit
        Consensus con = Consensus.getConsensus();
        // If you're having speed issues, try adding "Fast" to the lists of flags below.
        TorSocket sock = new TorSocket(con.getRandomORWithFlag("Guard,Fast,Running,Valid"));
        TorCircuit circ = sock.createCircuit(true);
        circ.create();
        circ.extend(con.getRandomORWithFlag("Exit,Fast,Valid,Running,HSDir".split(","), PORT));
        circ.setBlocking(false);

        // setup server socket and select
        ServerSocketChannel serverSock = ServerSocketChannel.open();
        serverSock.socket().bind(new InetSocketAddress(LISTENPORT));
        serverSock.configureBlocking(false);
        Selector select = Selector.open();
        serverSock.register(select, SelectionKey.OP_ACCEPT);

        while(true) {
            select.select(1000);

            Set keys = select.selectedKeys();
            Iterator iterator = keys.iterator();
            while (iterator.hasNext()) {
                SelectionKey k = (SelectionKey) iterator.next();

                if (!k.isValid())
                    continue;

                // new connection?
                if (k.isAcceptable() && k.channel() == serverSock) {
                    // new client
                    SocketChannel csock = serverSock.accept();
                    if(csock == null)
                        continue;
                    System.out.println("new client conn");
                    csock.configureBlocking(false);
                    csock.register(select, SelectionKey.OP_READ);
                    clients.put(csock, new PortFwdClient(csock, circ, REMOTE, PORT));

                } else {
                    // data on client socket
                    PortFwdClient cl = clients.get(k.channel());
                    if(cl!=null)
                        cl.newClientData();

                }
            }
        }
    }

    // represents a port forward client/server pair
    static class PortFwdClient implements TorStream.TorStreamListener {
        SocketChannel s;
        TorCircuit circ;
        TorStream stream;

        PortFwdClient(SocketChannel s, TorCircuit circ, String host, int port) {
            this.s = s;
            this.circ = circ;

            try {
                // establish stream
                if(host.equals("DIR"))
                    stream = circ.createDirStream(this);
                else
                    stream = circ.createStream(host, port, this);
            } catch (IOException e) {
                removeMe();
            }

        }

        // data from remote host (e.g. tor endpoint)
        @Override
        public void dataArrived(TorStream stream) {
            try {
                int availBytes = stream.getInputStream().available();
                byte buf[] = new byte[availBytes];
                stream.getInputStream().read(buf);
                s.write(ByteBuffer.wrap(buf));
            } catch (IOException e) {
                removeMe();
            }
        }

        @Override public void connected(TorStream s) {  }
        @Override public void disconnected(TorStream s) { removeMe();  }
        @Override public void failure(TorStream s) { removeMe();  }

        // data from client
        public void newClientData() {
            try {
                ByteBuffer inbuf = ByteBuffer.allocate(16384);
                if (s.read(inbuf) < 1)
                    return;
                inbuf.flip();
                byte buf[]= new byte[inbuf.limit()];
                inbuf.get(buf);
                stream.send(buf);
            } catch (IOException e) {
                removeMe();
            }
        }

        // tear down this pair
        public void removeMe() {
            try {
                stream.destroy();
                s.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            clients.remove(s);
        }
    }

}
