package tor;

import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
		BufferedReader rdr = new BufferedReader(new InputStreamReader(conn.openStream()));
		String ln;
		boolean save = false;
		String onionkey = "";
		while ((ln = rdr.readLine()) != null) {
			if (ln.contains("onion-key"))
				save = true;
			else if(save && ln.contains("---END RSA"))
				break;
			else if(!ln.contains("BEGIN") && save)
				onionkey += ln;
			
		}
		pubKey = TorCrypto.asn1GetPublicKey(Base64.decodeBase64(onionkey));
		/*X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		kf.generatePublic(spec);*/
		
		return pubKey;
	}

	@Override
	public String toString() {
		return "OnionRouter [name=" + name + ", ip=" + ip + ", orport="
				+ orport + ", identityhash=" + identityhash + "]";
	}

}
