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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import tor.util.TorDocumentParser;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.HashSet;

public class OnionRouter {
    String name;
	InetAddress ip;
	int orport;
	int dirport;
	PublicKey pubKey = null;
	public String identityhash;
    public HashSet<String> flags = new HashSet<String>();
    public byte[] pubKeyraw;

    public OnionRouter(String _nm, String _ident, String _ip, int _orport, int _dirport) throws UnknownHostException {
		name = _nm;
		ip = InetAddress.getByName(_ip);
		orport = _orport;
		dirport = _dirport;
		identityhash = _ident;
	}
	
	public PublicKey getPubKey() throws IOException {
		if (pubKey != null)
			return pubKey;
        TorDocumentParser rdr = new TorDocumentParser(Consensus.getConsensus().getRouterDescriptor(identityhash));

        pubKeyraw = Base64.decodeBase64(rdr.getItem("onion-key"));
        pubKey = TorCrypto.asn1GetPublicKey(pubKeyraw);

		return pubKey;
	}

	@Override
	public String toString() {
		return "OnionRouter [name=" + name + ", ip=" + ip + ", orport="
				+ orport + ", identityhash=" + identityhash + "]";
	}

}
