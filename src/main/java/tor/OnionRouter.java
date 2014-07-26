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
		URL conn = new URL("http://"+Consensus.DIRSERV+"/tor/server/fp/"+identityhash);
        String doc = IOUtils.toString(conn.openStream());
        TorDocumentParser rdr = new TorDocumentParser(doc);

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
