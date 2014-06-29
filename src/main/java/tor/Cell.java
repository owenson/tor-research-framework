package tor;

import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Cell {
	public int circId;
	public int cmdId;
	public byte payload[];

	public static final int CREATE = 1;
	public static final int CREATED = 2;
	public static final int RELAY = 3;
	public static final int DESTROY = 4;
	public static final int NETINFO = 8;
	public static final int RELAY_EARLY = 9;
	public static final int VERSIONS = 7;
	public static final int CERTS = 129;
	public static final int AUTH_CHALLENGE = 130;
	public static final int AUTHENTICATE = 131;
	public static final int AUTHORIZE = 132;
	
	public Cell(int circ, int cmd, byte[] pl) {
		circId = circ;
		cmdId = cmd;
		payload = pl;
	}

	@Override
	public String toString() {
		return "Cell [circId=" + circId + ", cmdId=" + cmdId + ", payload="
				+ Hex.encodeHexString(payload) + "]";
	}

    // prepare for sending
    public byte [] getBytes() {
        byte cell[];

        if (cmdId == 7 || cmdId >= 128)
            cell = new byte[3 + 2 + payload.length];
        else
            cell = new byte[512];

        ByteBuffer buf = ByteBuffer.wrap(cell);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) circId);
        buf.put((byte) cmdId);

        if (cmdId == 7 || cmdId >= 128)
            buf.putShort((short) payload.length);

        buf.put(payload);
        //System.out.println("Sending:" + byteArrayToHex(cell));
        return cell;
    }

    public static Cell fromBytes(byte []in) {
        ByteBuffer buf = ByteBuffer.wrap(in);
        int circid = buf.getShort();
        int cmdId = buf.get() & 0xff;
        int pllength = 509;

        if(cmdId == 7 || cmdId >= 128)
            pllength = buf.getShort();

        byte payload[] = new byte[pllength];
        buf.get(payload);

        return new Cell(circid, cmdId, payload);
    }
}
