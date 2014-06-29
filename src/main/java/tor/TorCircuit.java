package tor;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import tor.util.UniqueQueue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.TreeMap;

public class TorCircuit {

	public static BigInteger DH_G = new BigInteger("2");
	public static BigInteger DH_P = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
	
	private static int circId_counter = 1;
	int circId = 0;
	
	public static short streamId_counter = 1;
	
	public static final int RELAY_BEGIN = 1;
	public static final int RELAY_DATA = 2;
	public static final int RELAY_END = 3;
	public static final int RELAY_CONNECTED = 4;
    public static final int RELAY_SENDME = 5;
	public static final int RELAY_EXTEND = 6;
	public static final int RELAY_EXTENDED = 7;
	public static final int RELAY_EARLY = 9;
	public static final int RELAY_RESOLVE = 11;
	public static final int RELAY_RESOLVED = 12;
	public static final int RELAY_BEGIN_DIR = 13;
	
	// temp vars for created/extended
	private BigInteger temp_x;
	private OnionRouter temp_r;
	
	// this circuit hop
	private LinkedList<OnionRouter> circuitToBuild = new LinkedList<OnionRouter>();
	private ArrayList<TorHop> hops = new ArrayList<TorHop>();
	
    public enum STATES { NONE, CREATING, EXTENDING, READY, DESTROYED }
	public STATES state = STATES.NONE;
    private Object stateNotify = new Object();
	
	// list of active streams for this circuit
	TreeMap<Integer, TorStream> streams = new TreeMap<Integer, TorStream>();
	// streams with packets to send
	/**
	 * 
	 */
	UniqueQueue <TorStream> streamsSending = new UniqueQueue<TorStream>();

	TorSocket sock;
	
	public TorCircuit(TorSocket sock) {
		circId = circId_counter++;
		this.sock = sock;
	}
	
	public TorCircuit(int cid, TorSocket sock) {
		circId = cid;
		this.sock = sock;
	}

    public void setState(STATES newState) {
        synchronized (stateNotify) {
            state = newState;
            stateNotify.notifyAll();
        }
    }

    public void waitForState(STATES desired) {
        while(true) {
            synchronized (stateNotify) {
                try {
                    stateNotify.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            if(state.equals(desired))
                return;
        }
    }
	
	/**
	 * Utility function to create routes
	 * 
	 * @param hopList Comma separated list on onion router names
	 * @throws IOException 
	 */
	public void createRoute(String hopList) throws IOException {
		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");
		
		String hops[] = hopList.split(",");
		create(sock.firstHop); // must go to first hop first
		for(String s : hops) {
			circuitToBuild.add(sock.getConsensus().getRouterByName(s));
		}
	}

	/**
	 * Sends a create cell to specified hop (usually first hop that we're already connected to)
	 * 
	 * @param r Hop
	 */
	public void create(OnionRouter r) throws IOException  {
		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");
		
		setState(STATES.CREATING);
		sock.sendCell(circId, Cell.CREATE, createPayload(r));
	}
	
	/**
	 * Builds create cell payload (e.g. tap handshake)
	 * 
	 * @param r Hop to create to
	 * @return Payload
	 * @throws IOException 
	 */
	private byte[] createPayload(OnionRouter r) throws IOException  {
		byte privkey[] = new byte[40];
		
		// generate priv key
		TorCrypto.rnd.nextBytes(privkey);
		temp_x = new BigInteger(privkey);
		temp_r = r;
		
		// generate pub key
		BigInteger pubKey = DH_G.modPow(temp_x, DH_P);
		byte pubKeyByte[] = TorCrypto.BNtoByte(pubKey);
		return TorCrypto.hybridEncrypt(pubKeyByte, r.getPubKey());
	}
	
	/**
	 * Builds a relay cell payload (not including cell header, only relay header)
	 * 
	 * @param toHop Hop that it's destined for
	 * @param cmd Command ID, see RELAY_
	 * @param stream Stream ID
	 * @param payload Relay cell data
	 * @return Constructed relay payload
	 */
	protected byte[] buildRelay(TorHop toHop, int cmd, short stream, byte[] payload) {
		byte [] fnl = new byte[509];
		ByteBuffer buf = ByteBuffer.wrap(fnl);
		buf.put((byte)cmd);
		buf.putShort((short) 0); // recognised
		buf.putShort(stream);
		buf.putInt(0); // digest
		buf.putShort((short) payload.length);
		buf.put(payload);
		
		toHop.df_md.update(fnl);
		MessageDigest md;
		try {
			md = (MessageDigest) toHop.df_md.clone();
			
			byte digest[] = md.digest();
			
			byte [] fnl_final = new byte[509];
			System.arraycopy(digest, 0, fnl, 5, 4);
			
			return fnl;
		} catch (CloneNotSupportedException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	/**
	 * Wraps data in onion skins for sending down circuit
	 * 
	 * @param data Data to wrap/encypr
	 * @return Wrapped/encrypted data
	 */
	private byte[] encrypt(byte []data) {
		for (int i = hops.size()-1; i >= 0; i--) {
			data = hops.get(i).encrypt(data);
		}
		return data;
	}
	
	/**
	 * Removes onion skins for received data
	 * 
	 * @param data Encrypted data for onion skin removal.
	 * @return Decrypted data.
	 */
	private byte[] decrypt(byte []data) {
		for (int i = 0; i<hops.size(); i++) {
			data = hops.get(i).decrypt(data);
            if(data[1] == 0 && data[2] == 0) // recognised
                return data; // TODO- also check hash!!
		}
		return data;
	}

    public TorHop getLastHop() {
        return hops.get(hops.size()-1);
    }
	
	/**
	 * Sends an extend cell to extend the circuit to specified hop
	 * 
	 * @param nextHop Hop to extend to
	 * @throws  
	 */
	public void extend(OnionRouter nextHop) throws IOException  {
		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");
		
		TorHop lastHop = getLastHop();
		
		byte create[] =  createPayload(nextHop);
		byte extend[] = new byte [4 + 2 + create.length + TorCrypto.HASH_LEN];
		ByteBuffer buf = ByteBuffer.wrap(extend);
		buf.put(nextHop.ip.getAddress());
		buf.putShort((short)nextHop.orport);
		buf.put(create);
		buf.put(Hex.decode(nextHop.identityhash));
		
		send(extend, RELAY_EXTEND, true, (short)0);
		//byte []payload = encrypt(buildRelay(lastHop, RELAY_EXTEND, (short)0, extend));
		//sock.sendCell(circId, Cell.RELAY_EARLY, payload);
		
		setState(STATES.EXTENDING);
	}
	
	/**
	 * Handles created cell (also used for extended cell as payload the same)
	 * 
	 * @param in Cell payload (e.g. handshake data)
	 */
	private void handleCreated(byte in[])  {
		// other side's public key
		byte y_bytes[] = Arrays.copyOfRange(in, 0, TorCrypto.DH_LEN);
		
		// kh for verification of derivation
		byte kh[] = Arrays.copyOfRange(in,  TorCrypto.DH_LEN, TorCrypto.DH_LEN+TorCrypto.HASH_LEN);
		
		//calculate g^xy shared secret
		BigInteger secret = TorCrypto.byteToBN(y_bytes).modPow(temp_x, DH_P);
		
		// derive key data data
		byte kdf[] = TorCrypto.torKDF(TorCrypto.BNtoByte(secret), 3*TorCrypto.HASH_LEN + 2*TorCrypto.KEY_LEN);
		
		// ad hop
		hops.add(new TorHop(kdf, kh, temp_r));

        if(circuitToBuild.isEmpty())
            setState(STATES.READY);
	}
	
	/**
	 * Creates a stream using this circuit and connects to a host
	 * 
	 * @param host Hostname/ip
	 * @param port Port
	 * @param list A listener for stream events
	 * 
	 * @return TorStream object
	 */
	public TorStream createStream(String host, int port, TorStream.TorStreamListener list) throws IOException {
		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");
		
		byte b[] = new byte[100];
		ByteBuffer buf = ByteBuffer.wrap(b); 
		buf.put((host+":"+port).getBytes("UTF-8"));
		buf.put((byte)0); // null terminator
		buf.putInt(0);
		int stid = streamId_counter++;
		send(b, RELAY_BEGIN, false, (short) stid);
		TorStream st = new TorStream(stid, this, list);
		streams.put(new Integer(stid), st);
		return st;
	}
	
	/**
	 * Gererates a relay cell, encrypts and sends it
	 * 
	 * @param payload Relay payload
	 * @param relaytype Type of relay cell (see RELAY_)
	 * @param early Whether to use an early cell (needed for EXTEND only)
	 * @param stream Stream ID
	 */
	public void send(byte []payload, int relaytype, boolean early, short stream) throws IOException {
		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");

        if(relaytype == RELAY_DATA)
            sendWindow--;

		byte relcell[] = buildRelay(hops.get(hops.size() - 1), relaytype, stream, payload);
		sock.sendCell(circId, early ? Cell.RELAY_EARLY:Cell.RELAY, encrypt(relcell));
	}
	
	/**
	 * Handles cell for this circuit
	 * 
	 * @param c Cell to handle
	 * 
	 * @return Successfully handled
	 */
    public int receiveWindow = 1000;
    public int sendWindow = 1000;


	public boolean handleCell(Cell c) throws IOException {
		boolean handled = false;
        if(state == STATES.READY)
            receiveWindow--;

        if(receiveWindow < 900) {
            send(new byte[] {00}, RELAY_SENDME, false, (short)0);
            receiveWindow += 100;
        }

		if(state == STATES.DESTROYED)
			throw new RuntimeException("Trying to use destroyed circuit");
		
		if(c.cmdId == Cell.CREATED) // create
		{
			handleCreated(c.payload);
			
			if(!circuitToBuild.isEmpty()) // more?
				extend(circuitToBuild.removeFirst());
			
			handled = true;	
		} 
		else if (c.cmdId == Cell.RELAY) // relay cell
		{
			c.payload = decrypt(c.payload);
			
			// decode relay header
			ByteBuffer buf = ByteBuffer.wrap(c.payload);
			int cmd = buf.get();
			if(buf.getShort() != 0)
				throw new RuntimeException("Invalid relay cell");
			
			int streamid = buf.getShort();
			TorStream stream = streams.get(new Integer(streamid));
			
			if(streamid > 0 && stream == null)
				System.out.println("invalid stream id "+streamid);
			
			int digest = buf.getInt();
			int length = buf.getShort();
			byte data[] = Arrays.copyOfRange(c.payload, 1 + 2 + 2 + 4 + 2, 1 + 2 + 2 + 4 + 2 + length);
			
			switch(cmd) {
				case RELAY_EXTENDED: // extended
					handleCreated(data);

					if(!circuitToBuild.isEmpty()) // needs extending further?
						extend(circuitToBuild.removeFirst());
                    else
                        setState(STATES.READY);
					break;
				case RELAY_CONNECTED:
					if(stream != null) 
						stream.notifyConnect();
					break;
                case RELAY_SENDME:
                    if(streamid == 0)
                        sendWindow += 100;
                    System.out.println("RELAY_SENDME circ "+circId+" Stream "+streamid+ " cur window "+sendWindow);
                    break;
                case RELAY_DATA:
					if(stream != null) 
						stream._putRecved(data);
					break;
				case RELAY_END:
					if(stream != null) {
						stream.notifyDisconnect();
						streams.remove(new Integer(streamid));
					}					
					break;
				default:
					System.out.println("unknown relay cell cmd "+cmd);
			}
			handled = true;
		}
		else if (c.cmdId == Cell.DESTROY) {
			System.out.println("Circuit destroyed "+circId);
            System.out.println("Reason: "+Hex.toHexString(c.payload));
            for (Iterator<TorStream> iterator = streams.values().iterator(); iterator.hasNext(); ) {
                TorStream s = iterator.next();
                s.notifyDisconnect();
            }
			setState(STATES.DESTROYED);
			handled = true;
		}
		
		return handled;
	}

}
