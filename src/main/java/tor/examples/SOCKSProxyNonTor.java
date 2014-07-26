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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

/**
 * Created by gho on 27/06/14.
 */
public class SOCKSProxyNonTor {
    // socks client class
    class SocksClient {
        SocketChannel client, remote;
        boolean connected;
        long lastData = 0;

        SocksClient(SocketChannel c) throws IOException {
            client = c;
            client.configureBlocking(false);
            lastData = System.currentTimeMillis();
        }

        public void newRemoteData(Selector selector, SelectionKey sk) throws IOException {
            ByteBuffer buf = ByteBuffer.allocate(1024);
            if(remote.read(buf) == -1)
                throw new IOException("disconnected");
            lastData = System.currentTimeMillis();
            buf.flip();
            client.write(buf);
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

                final int port = inbuf.getShort();

                final byte ip[] = new byte[4];
                // fetch IP
                inbuf.get(ip);

                InetAddress remoteAddr = InetAddress.getByAddress(ip);

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

                remote = SocketChannel.open(new InetSocketAddress(remoteAddr, port));

                ByteBuffer out = ByteBuffer.allocate(20);
                out.put((byte)0);
                out.put((byte) (remote.isConnected() ? 0x5a : 0x5b));
                out.putShort((short) port);
                out.put(remoteAddr.getAddress());
                out.flip();
                client.write(out);

                if(!remote.isConnected())
                    throw new IOException("connect failed");

                remote.configureBlocking(false);
                remote.register(selector, SelectionKey.OP_READ);

                connected = true;
            } else {
                ByteBuffer buf = ByteBuffer.allocate(1024);
                if(client.read(buf) == -1)
                    throw new IOException("disconnected");
                lastData = System.currentTimeMillis();
                buf.flip();
                remote.write(buf);
            }
        }
    }

    static ArrayList <SocksClient> clients = new ArrayList<SocksClient>();

    // utility function
    public SocksClient addClient(SocketChannel s) {
        SocksClient cl;
        try {
            cl = new SocksClient(s);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        clients.add(cl);
        return cl;
    }

    public SOCKSProxyNonTor() throws IOException {
        ServerSocketChannel socks = ServerSocketChannel.open();
        socks.socket().bind(new InetSocketAddress(8000));
        socks.configureBlocking(false);
        Selector select = Selector.open();
        socks.register(select, SelectionKey.OP_ACCEPT);

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
                if (k.isAcceptable() && k.channel() == socks) {
                    // server socket
                    SocketChannel csock = socks.accept();
                    if (csock == null)
                        continue;
                    addClient(csock);
                    csock.register(select, SelectionKey.OP_READ);
                } else if (k.isReadable()) {
                    // new data on a client/remote socket
                    for (int i = 0; i < clients.size(); i++) {
                        SocksClient cl = clients.get(i);
                        try {
                            if (k.channel() == cl.client) // from client (e.g. socks client)
                                cl.newClientData(select, k);
                            else if (k.channel() == cl.remote) {  // from server client is connected to (e.g. website)
                                cl.newRemoteData(select, k);
                            }
                        } catch (IOException e) { // error occurred - remove client
                            cl.client.close();
                            if (cl.remote != null)
                                cl.remote.close();
                            k.cancel();
                            clients.remove(cl);
                        }

                    }
                }
            }

            // client timeout check
            for (int i = 0; i < clients.size(); i++) {
                SocksClient cl = clients.get(i);
                if((System.currentTimeMillis() - cl.lastData) > 30000L) {
                    cl.client.close();
                    if(cl.remote != null)
                        cl.remote.close();
                    clients.remove(cl);
                }
            }
            if(clients.size() != lastClients) {
                System.out.println(clients.size());
                lastClients = clients.size();
            }
        }
    }

    public static void main(String[] args) throws IOException {
        new SOCKSProxyNonTor();
    }
}
