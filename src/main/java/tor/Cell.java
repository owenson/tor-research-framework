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

import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Cell {
    public long circId;
    public int cmdId;
    public byte payload[];

    public static final int PADDING = 0;
    public static final int CREATE = 1;
    public static final int CREATED = 2;
    public static final int RELAY = 3;
    public static final int DESTROY = 4;
    public static final int NETINFO = 8;
    public static final int RELAY_EARLY = 9;
    public static final int VERSIONS = 7;
    public static final int VPADDING = 128;
    public static final int CERTS = 129;
    public static final int AUTH_CHALLENGE = 130;
    public static final int AUTHENTICATE = 131;
    public static final int AUTHORIZE = 132;

    public Cell(long circ, int cmd, byte[] pl) {
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
    public byte[] getBytes(int protocolVersion) {
        byte cell[];

        if (cmdId == 7 || cmdId >= 128)
            cell = new byte[(protocolVersion<4?3:5) + 2 + payload.length];
        else
            cell = new byte[protocolVersion<4?512:514];

        ByteBuffer buf = ByteBuffer.wrap(cell);
        buf.order(ByteOrder.BIG_ENDIAN);
        if(protocolVersion<4)
            buf.putShort((short) circId);
        else
            buf.putInt((int)circId);
        buf.put((byte) cmdId);

        if (cmdId == 7 || cmdId >= 128)
            buf.putShort((short) payload.length);

        if (payload != null)
            buf.put(payload);
        //System.out.println("Sending:" + byteArrayToHex(cell));
        return cell;
    }

//    public static Cell fromBytes(byte[] in) {
//        ByteBuffer buf = ByteBuffer.wrap(in);
//        int circid = buf.getShort();
//        int cmdId = buf.get() & 0xff;
//        int pllength = 509;
//
//        if (cmdId == 7 || cmdId >= 128)
//            pllength = buf.getShort();
//
//        byte payload[] = new byte[pllength];
//        buf.get(payload);
//
//        return new Cell(circid, cmdId, payload);
//    }
}
