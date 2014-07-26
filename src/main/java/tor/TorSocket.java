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
package tor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.IOUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.TreeMap;
import java.util.concurrent.LinkedBlockingQueue;

public class TorSocket {

	private static Consensus consensus;
	
	SSLSocket sslsocket;
	OutputStream out;
	InputStream in;
	
	OnionRouter firstHop; // e.g. hop connected to
	
	// circuits for this socket
	TreeMap<Integer, TorCircuit> circuits = new TreeMap<Integer, TorCircuit>();
    LinkedBlockingQueue<Cell> sendQueue = new LinkedBlockingQueue<Cell>();
    enum STATES { INITIALISING, READY };

    private STATES state = STATES.INITIALISING;
    private Object stateNotify = new Object();

	/**
	 * Send a cell given payload
	 * 
	 * @param circid Circuit ID
	 * @param cmd Cell Command.  See Cell.*
	 * @param payload Cell Payload
	 * 
	 * @return Success or failure
	 */
	public void sendCell(int circid, int cmd, byte[] payload)
			throws IOException {
        try {
            sendQueue.put(new Cell(circid, cmd, payload));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void sendCell(Cell c)
            throws IOException {
        try {
            sendQueue.put(c);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void processSendQueue() {
        while(true) {
            while (!sendQueue.isEmpty())
                try {
                    out.write(sendQueue.take().getBytes());
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
        }
	}

    private byte[] blockingRead(int length) throws IOException {
       byte buf[] = new byte[length];
       return IOUtils.readFully(in, length, true);

//       int off = 0;
//       while(length>off) {
//           int rlen = in.read(buf, off, length-off);
//           if(rlen == -1)
//               throw new IOException("failed read");
//           off+=rlen;
//       }
//       return buf;
    }
	
	/**
	 * Receive a cell from the socket and decode it into a Cell object
	 * 
	 * @return Cell object
	 */
	public Cell recvCell() throws IOException {
		byte hdr[] =  blockingRead(3);

		ByteBuffer buf = ByteBuffer.wrap(hdr);
		buf.order(ByteOrder.BIG_ENDIAN);
		int circid = buf.getShort();
		int cmdId = buf.get() & 0xff;
		int pllength = 509;
			
		if(cmdId == 7 || cmdId >= 128) {
			pllength = ByteBuffer.wrap(blockingRead(2)).getShort();
		}
		
		byte payload[] = blockingRead(pllength);

		return new Cell(circid, cmdId, payload);
	}

	/**
	 * Sends a NETINFO cell (used in connection init)
	 */
	public void sendNetInfo() throws IOException {
		byte nibuf[] = new byte[4 + 2 + 4 + 3 + 4]; 
		byte[] remote = sslsocket.getInetAddress().getAddress();
		byte[] local = sslsocket.getLocalAddress().getAddress();
		int epoch = (int)(System.currentTimeMillis()/1000L);
		ByteBuffer buf = ByteBuffer.wrap(nibuf);
		buf.putInt(epoch);
		buf.put(new byte[] {04, 04});   // remote's address
		buf.put(remote);
		buf.put(new byte[] {01, 04, 04});  // our address
		buf.put(local);
		sendCell(0, Cell.NETINFO, nibuf);
	}

    public void setState(STATES newState) {
        synchronized (stateNotify) {
            this.state = newState;
            this.stateNotify.notify();
        }
    }
	/**
	 * Main loop.  Handles incoming cells and sends any data waiting to be send down circuits/streams
	 */
	public void receiveHandlerLoop() {
        while(true) {
            // receive a cell
            Cell c= null;
            try {
                c = recvCell();

                switch(c.cmdId) {
                    case Cell.NETINFO:
                        sendNetInfo();
                        setState(STATES.READY);
                        break;
                }
                TorCircuit circ = circuits.get(new Integer(c.circId));
                if(circ == null || !circ.handleCell(c))
                    System.out.println("unhandled cell "+c);

            } catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
	}
	
	/**
	 * Creates a circuit
	 * 
	 * @return TorCircuit object
	 */
	public TorCircuit createCircuit(boolean blocking) {
		// TODO Auto-generated method stub
		TorCircuit circ = new TorCircuit(this);
        circ.setBlocking(blocking);
		circuits.put(new Integer(circ.circId), circ);
		return circ;
	}
	
	/*public TorSocket(OnionRouter guard) throws IOException  {
		this(guard.ip.getHostAddress(), guard.orport);
	}*/
	
	/**
	 * Main constructor. Connects and does connection setup.
	 * 
	 * @param host Hostname/IP string
	 * @param port Port
	 */
	public TorSocket(OnionRouter fh) throws IOException  {

		if(consensus == null) consensus = Consensus.getConsensus();

		//firstHop = consensus.getRouterByIpPort(host, port);
        firstHop = fh;
		if(firstHop == null)
			throw new RuntimeException("Couldn't find router ip in consensus");
		
		Security.addProvider(new BouncyCastleProvider());
		// fake trust manager to accept all certs
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			@Override
			public void checkClientTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {
				// TODO Auto-generated method stub

			}

			@Override
			public void checkServerTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {
				// TODO Auto-generated method stub

			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				// TODO Auto-generated method stub
				return null;
			}

		} };

		SSLContext sc;
		
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		// connect
		sslsocket = (SSLSocket) sc.getSocketFactory().createSocket(firstHop.ip, firstHop.orport);

		out = sslsocket.getOutputStream();
		in = sslsocket.getInputStream();

        new Thread(new Runnable() {
            @Override
            public void run() {
                processSendQueue();
            }
        }).start();

        new Thread(new Runnable() {
            @Override
            public void run() {
                receiveHandlerLoop();
            }
        }).start();

		// versions cell
		sendCell(0, Cell.VERSIONS, new byte[] { 00, 03 });

        while(state != STATES.READY) {
            synchronized (stateNotify) {
                try {
                    stateNotify.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
	}
}
