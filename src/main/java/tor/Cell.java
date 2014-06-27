package tor;

import org.apache.commons.codec.binary.Hex;

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
}
