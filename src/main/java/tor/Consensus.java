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
import org.apache.commons.codec.binary.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.zip.InflaterInputStream;

public class Consensus {
	public final static String DIRSERV = "86.59.21.38";
	
	public TreeMap<String, OnionRouter> routers = new TreeMap<String, OnionRouter>();
    String authorities[] = {    "moria1 orport=9101 v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
            "tor26 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
            "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
            "Tonga orport=443 bridge 82.94.251.203:80 4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
            "turtles orport=9090 v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
            "gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
            "dannenberg orport=443 v3ident=585769C78764D58426B8B52B6651A5A71137189A 193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
            "urras orport=80 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
            "maatuska orport=80 v3ident=49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
            "Faravahar orport=443 v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"
    };
	
	public Consensus() throws IOException {
        Pattern p = Pattern.compile("/([0-9]+\\.){4}\\:[0-9]+/");
        for (String auth : authorities) {
            String sp[] = auth.split(" ");
            String ipp[] = sp[3].split(":");
            System.out.println("Fetching consensus from authority: "+sp[0]);
            if(fetchConsensus(ipp[0], Integer.parseInt(ipp[1])))
                return;
        }
        throw new RuntimeException("Cant get consensus");
    }

    private boolean fetchConsensus(String ip, int dirport) {
        try {
            URL conurl = new URL("http://" + ip + ":" + dirport + "/tor/status-vote/current/consensus.z");

            BufferedReader in = new BufferedReader(new InputStreamReader(new InflaterInputStream(conurl.openStream())));
            String ln = null;
            OnionRouter cur = null;
            while ((ln = in.readLine()) != null)
                if (ln.startsWith("r")) {
                    String dat[] = ln.split(" ");
                    if (dat.length < 8)
                        continue;
                    String identityhex = Hex.encodeHexString(Base64.decodeBase64(dat[2]));
                    cur = new OnionRouter(dat[1], identityhex, dat[6], Integer.parseInt(dat[7]), Integer.parseInt(dat[8]));

                    routers.put(identityhex, cur);
                } else if (ln.startsWith("s") && cur != null) {
                    for (String s : ln.split(" "))
                        if (!s.equals("s"))
                            cur.flags.add(s);
                }
        } catch (MalformedURLException e) {
            return false;
        } catch (UnknownHostException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    private static Consensus consensus = null;

    public static Consensus getConsensus() {
        if(consensus == null) {
            try {
                consensus = new Consensus();
            } catch (IOException e) {
                throw new RuntimeException("Cant get consensus: "+e);
            }
        }
        return consensus;
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

    public TreeMap<String,OnionRouter> getORsWithFlag(String flag) {
        TreeMap<String,OnionRouter> map = new TreeMap<String,OnionRouter>();
        for (OnionRouter r : routers.values()) {
            if(r.flags.contains(flag)) {
                map.put(r.identityhash, r);
            }
        }
        return map;
    }
}
