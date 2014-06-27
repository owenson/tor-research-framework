package tor;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.TreeMap;
import java.util.zip.InflaterInputStream;

public class Consensus {
	public final static String DIRSERV = "86.59.21.38";
	
	TreeMap<String, OnionRouter> routers = new TreeMap<String, OnionRouter>();
	
	public Consensus() throws IOException {
		URL conurl = new URL("http://"+DIRSERV+"/tor/status-vote/current/consensus.z");
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new InflaterInputStream(conurl.openStream())));
		String ln = null;
		while((ln = in.readLine()) != null)
			if (ln.startsWith("r")) {
				String dat[] = ln.split(" ");
				if(dat.length < 8)
					continue;
				String identityhex = Hex.encodeHexString(Base64.decodeBase64(dat[2]));
				
				routers.put(identityhex, new OnionRouter(dat[1], identityhex, dat[6], Integer.parseInt(dat[7]), Integer.parseInt(dat[8])));
			}
	}
	
	public OnionRouter getRouterByName(String nm) {
		for (OnionRouter r : routers.values())
			if (r.name.equals(nm))
				return r;
		throw new RuntimeException("unknown router: "+nm);
	}

	public OnionRouter getRouterByIpPort(String addr, int port) {
		for (OnionRouter r : routers.values())
			if (r.ip.getHostAddress().equals(addr) && r.orport == port)
				return r;
		throw new RuntimeException("unknown router");
	}
}
