package tor.examples;

import tor.OnionRouter;
import tor.TorCircuit;
import tor.TorSocket;
import tor.TorStream;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.Iterator;
import java.util.Set;

/**
 * Created by gho on 27/06/14.
 */
public class SOCKSProxy {
    public static void handleRequest(final SocketChannel s, TorCircuit circ) throws IOException {
        try {
            System.out.println("new request");

            final DataInputStream in = new DataInputStream(Channels.newInputStream(s));
            final DataOutputStream out = new DataOutputStream(Channels.newOutputStream(s));

            // read socks header
            int ver = in.readByte();
            if (ver != 4) {
                System.out.println("incorrect version " + ver);
                s.close();
                return;
            }
            int cmd = in.readByte();

            // check supported command
            if (cmd != 1) {
                s.close();
                return;
            }

            final int port = in.readShort();

            final byte ip[] = new byte[4];
            // fetch IP
            in.read(ip);

            InetAddress _remote = InetAddress.getByAddress(ip);

            while ((in.readByte()) != 0) ; // username

            // hostname provided, not IP
            if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0) { // host provided
                String host = "";
                byte b;
                while ((b = in.readByte()) != 0) {
                    host += b;
                }
                _remote = InetAddress.getByName(host);
                System.out.println(host + _remote);
            }
            final InetAddress remote = _remote;

            // connect to remote host
            SocketChannel rms = SocketChannel.open(new InetSocketAddress(remote, port));
            circ.createStream(remote.getHostAddress(), port, new TorStream.TorStreamListener() {

                @Override
                public void dataArrived(TorStream stream) {
                    System.out.println("data arrived");
                    try {
                        byte b[] = stream.recv(-1, true);
                        s.write(ByteBuffer.wrap(b));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                @Override
                public void connected(final TorStream stream) {
                    System.out.println("connected");
                    try {
                        // write socks header response
                        out.writeByte(0);
                        out.writeByte(0x5a);
                        out.writeShort(port);
                        out.write(remote.getAddress());

                        // begin proxying
                        final Selector selector = Selector.open();
                        s.configureBlocking(false);
                        s.register(selector, SelectionKey.OP_READ);

//            OutputStream rout = Channels.newOutputStream(rms);
//            InputStream rin = Channels.newInputStream(rms);

                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    while (true) {
                                        selector.select(1000);
                                        Set keys = selector.selectedKeys();
                                        Iterator it = keys.iterator();
                                        while (it.hasNext()) {
                                            SelectionKey k = (SelectionKey) it.next();
//                    it.remove();
                                            ByteBuffer buf = ByteBuffer.allocate(1024);
                                            if (k.isReadable() && k.channel() == s) {
                                                if (s.read(buf) == -1)
                                                    return;
                                                buf.flip();
                                                stream.send(buf.array());
                                            }
                                        }
                                    }
                                } catch(IOException e) {

                                }
                            }
                        }).start();
                    } catch (IOException e) {
                        try {
                            stream.destroy();
                        } catch (IOException e1) {
                            e1.printStackTrace();
                        }
                    }

                }

                @Override
                public void disconnected(TorStream stream) {
                    System.out.println("disconnected");
                    try {
                        // write socks header response
                        out.writeByte(0);
                        out.writeByte(0x5b);
                        out.writeShort(port);
                        out.write(remote.getAddress());
                        s.close();
                    } catch (IOException e) {
                        System.out.println(e);
                    }

                }

                @Override
                public void failure(TorStream s) {
                    disconnected(s);

                }
            });


//            // write socks header response
//            out.writeByte(0);
//            out.writeByte(rms.isConnected() ? 0x5a:0x5b);
//            out.writeShort(port);
//            out.write(remote.getAddress());
//
//            if(!rms.isConnected()) {
//                s.close();
//                System.out.println("Cant connect to remote host");
//                return;
//            }


            //s.close();
        } catch(IOException e) {
            System.out.println(e);
        }
    }
    public static void main(String[] args) throws IOException {
        OnionRouter guard = TorSocket.getConsensus().getRouterByName("tor26");
		final TorSocket sock = new TorSocket(guard);

		// connected---------------
		final TorCircuit circ = sock.createCircuit();
		circ.createRoute("gho,edwardsnowden1");
        circ.waitForState(TorCircuit.STATES.READY);

		System.out.println("READY!!");

        final ServerSocketChannel socks = ServerSocketChannel.open();
        socks.socket().bind(new InetSocketAddress(8000));
        while(true) {
            final SocketChannel s = socks.accept();
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        handleRequest(s, circ);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }).start();
        }

    }
}
