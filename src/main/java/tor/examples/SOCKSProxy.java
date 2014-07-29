/*
        Tor Research Framework - easy to use tor client library/framework
        Copyright (C) 2014  Dr Gareth Owen <drgowen@gmail.com>
        www.ghowen.me / github.com/drgowen/tor-research-framework

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package tor.examples;

import tor.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/**
 * Created by gho on 27/06/14.
 */
public class SOCKSProxy {
    class SocksClient implements TorStream.TorStreamListener{
        SocketChannel client;
        boolean connected;
        long lastData = 0;
        TorStream stream;
        TorCircuit circ;
        InetAddress remoteAddr;
        int port;

        SocksClient(SocketChannel c, TorCircuit circ) throws IOException {
            client = c;
            client.configureBlocking(false);
            lastData = System.currentTimeMillis();
            this.circ = circ;
        }

        public void newClientData(Selector selector, SelectionKey sk) throws IOException {
            if(!connected) {
                ByteBuffer inbuf = ByteBuffer.allocate(512);
                if(client.read(inbuf)<1)
                    return;
                inbuf.flip();
                //inbufinbufinbufinb.get() final DataInputStream in = new DataInputStream(Channels.newInputStream(client));
//                final DataOutputStream out = new DataOutputStream(Channels.newOutputStream(client));

                // read socks header
                int ver = inbuf.get();
                if (ver != 4) {
                    throw new IOException("incorrect version" + ver);
                }
                int cmd = inbuf.get();

                // check supported command
                if (cmd != 1) {
                    throw new IOException("incorrect version");
                }

                port = inbuf.getShort();

                final byte ip[] = new byte[4];
                // fetch IP
                inbuf.get(ip);

                remoteAddr = InetAddress.getByAddress(ip);

                while ((inbuf.get()) != 0) ; // username

                // hostname provided, not IP
                if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0) { // host provided
                    String host = "";
                    byte b;
                    while ((b = inbuf.get()) != 0) {
                        host += b;
                    }
                    remoteAddr = InetAddress.getByName(host);
                    System.out.println(host + remoteAddr);
                }

                stream = circ.createStream(remoteAddr.getHostAddress(), port, this);
            } else {
                ByteBuffer buf = ByteBuffer.allocate(4096);
                int nlen = 0;
                if((nlen = client.read(buf)) == -1)
                    throw new IOException("disconnected");
                lastData = System.currentTimeMillis();
                buf.flip();
                byte b[] = new byte[nlen];
                buf.get(b);
                stream.send(b);
            }
        }

        @Override
        public void dataArrived(TorStream s) {
            try {
                if(!client.isConnected())
                    removeClient(this);

                int availBytes = s.getInputStream().available();
                byte buf[] = new byte[availBytes];
                s.getInputStream().read(buf);
                client.write(ByteBuffer.wrap(buf));
            } catch (IOException e) {
                try {
                    //System.out.println(e);
                    removeClient(this);
                } catch (IOException e1) {
                    //e1.printStackTrace();
                }
                //e.printStackTrace();
            }
            lastData = System.currentTimeMillis();

        }

        @Override
        public void connected(TorStream s) {
            ByteBuffer out = ByteBuffer.allocate(20);
            out.put((byte)0);
            out.put((byte) (0x5a));
            out.putShort((short) port);
            out.put(remoteAddr.getAddress());
            out.flip();
            try {
                client.write(out);
            } catch (IOException e) {
                try {
                    removeClient(this);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                System.out.println(e);
            }

            connected = true;
        }

        @Override
        public void disconnected(TorStream s) {
            try {
                removeClient(this);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        @Override
        public void failure(TorStream s) {
            disconnected(s);
            try {
                removeClient(this);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    static HashMap<SocketChannel,SocksClient> clients = new HashMap<SocketChannel,SocksClient>();

    // utility function
    public SocksClient addClient(SocketChannel s, TorCircuit circ) {
        SocksClient cl;
        try {
            cl = new SocksClient(s, circ);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        clients.put(s,cl);
        return cl;
    }

    public void removeClient(SocksClient c) throws IOException {
        c.client.close();
        c.stream.destroy();
        clients.remove(c.client);
    }

    long lastTimeoutCheck = 0;
    public SOCKSProxy() throws IOException {
        // connect through a guard
        OnionRouter guard = Consensus.getConsensus().getRouterByName("southsea0");
        TorSocket sock = new TorSocket(guard);

        // establish a circuit
        TorCircuit circ = sock.createCircuit(false);
        circ.createRoute("TorLand1");
        circ.waitForState(TorCircuit.STATES.READY, false);

        System.out.println("READY!!");

        ServerSocketChannel serverSock = ServerSocketChannel.open();
        serverSock.socket().bind(new InetSocketAddress(9050));
        serverSock.configureBlocking(false);
        Selector select = Selector.open();
        serverSock.register(select, SelectionKey.OP_ACCEPT);

        int lastClients = clients.size();
        // select loop
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
                    // server socket
                    SocketChannel csock = serverSock.accept();
                    if (csock == null)
                        continue;
                    addClient(csock, circ);
                    csock.register(select, SelectionKey.OP_READ);
                } else if (k.isReadable()) {
                    // new data on a client/remote socket
                    SocksClient cl = clients.get(k.channel());
                    try {
                        cl.newClientData(select, k);
                    } catch (IOException e) { // error occurred - remove client
                        cl.client.close();
                        k.cancel();
                        clients.remove(cl);
                        //System.out.println(e);
                    }

                }
            }

            // client timeout check
            if(System.currentTimeMillis() - lastTimeoutCheck > 15000) {
                lastTimeoutCheck = System.currentTimeMillis();
                Collection<SocksClient> clientsTmp = clients.values();
                for(SocksClient cl : clientsTmp) {
                    if((System.currentTimeMillis() - cl.lastData) > 30000L) {
                        cl.stream.destroy();
                        cl.client.close();
                        clients.remove(cl);
                    }
                }
                if(clients.size() != lastClients) {
                    System.out.println(clients.size());
                    lastClients = clients.size();
                }

            }
        }
    }

    public static void main(String[] args) throws IOException {
        new SOCKSProxy();
    }
}
