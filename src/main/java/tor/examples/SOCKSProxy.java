package tor.examples;

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
    public static void handleRequest(SocketChannel s) throws IOException {
        try {
            System.out.println("new request");

            DataInputStream in = new DataInputStream(Channels.newInputStream(s));
            DataOutputStream out = new DataOutputStream(Channels.newOutputStream(s));

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

            int port = in.readShort();

            InetAddress remote;
            byte ip[] = new byte[4];
            // fetch IP
            in.read(ip);

            remote = InetAddress.getByAddress(ip);

            while ((in.readByte()) != 0) ; // username

            // hostname provided, not IP
            if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0) { // host provided
                String host = "";
                byte b;
                while ((b = in.readByte()) != 0) {
                    host += b;
                }
                remote = InetAddress.getByName(host);
                System.out.println(host + remote);
            }

            // connect to remote host
            SocketChannel rms = SocketChannel.open(new InetSocketAddress(remote, port));

            // write socks header response
            out.writeByte(0);
            out.writeByte(rms.isConnected() ? 0x5a:0x5b);
            out.writeShort(port);
            out.write(remote.getAddress());

            if(!rms.isConnected()) {
                s.close();
                System.out.println("Cant connect to remote host");
                return;
            }

            // begin proxying
            Selector selector = Selector.open();
            s.configureBlocking(false);
            s.register(selector, SelectionKey.OP_READ);
            rms.configureBlocking(false);
            rms.register(selector, SelectionKey.OP_READ);

//            OutputStream rout = Channels.newOutputStream(rms);
//            InputStream rin = Channels.newInputStream(rms);

            while(true) {
                selector.select(1000);
                Set keys = selector.selectedKeys();
                Iterator it = keys.iterator();
                while (it.hasNext()) {
                    SelectionKey k = (SelectionKey) it.next();
//                    it.remove();
                    ByteBuffer buf = ByteBuffer.allocate(1024);
                    if (k.isReadable() && k.channel() == s) {
                        if(s.read(buf) == -1)
                            return;
                        buf.flip();
                        rms.write(buf);
                    } else if (k.isReadable() && k.channel() == rms) {
                        if(rms.read(buf) == -1)
                            return;
                        buf.flip();
                        s.write(buf);
                    }
                }
            }

            //s.close();
        } catch(IOException e) {
            System.out.println(e);
        }
    }
    public static void main(String[] args) throws IOException {
        final ServerSocketChannel socks = ServerSocketChannel.open();
        socks.socket().bind(new InetSocketAddress(8000));
        while(true) {
            final SocketChannel s = socks.accept();
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        handleRequest(s);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }).start();
        }

    }
}
