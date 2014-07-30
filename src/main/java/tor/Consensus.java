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
import org.apache.commons.io.IOUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.TreeMap;
import java.util.zip.InflaterInputStream;

public class Consensus {
	// --Commented out by Inspection (30/07/2014 06:24):
	// public final static String DIRSERV = "86.59.21.38";

    // The maximum number of connection tries to directory caches before falling back to authorities
    public final static int MAX_TRIES = 10;

	public TreeMap<String, OnionRouter> routers = new TreeMap<>();
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
	
	public Consensus() throws RuntimeException {
            fetchConsensus();
    }

    /***
     * Try random directories until we get a successful dir stream, falling back to the pre-configured authorities after MAX_TRIES,
     * or if we don't have an existing consensus
     *
     * @param path Desired dir path
     * @return InputStream for reading
     */
    public InputStream getDirectoryStream(String path) {
        return getDirectoryStream(path, true);
    }

    /***
     * Try random directories until we get a successful dir stream, falling back to the pre-configured authorities after MAX_TRIES,
     * or if we don't have an existing consensus
     *
     * If you're having speed issues, try adding "Fast" to the lists of flags below.
     *
     * @param path Desired dir path
     * @param useDirectoryCaches use directory caches, if an existing consensus is available
     * @return InputStream for reading
     * @throws RuntimeException when it fails to download path after MAX_TRIES tries
     */
    public InputStream getDirectoryStream(String path, Boolean useDirectoryCaches) throws RuntimeException {
        String directoryType = "directory cache";

        // Avoid recursion by checking for an existing consensus before calling getRandomORWithFlag()
        if (consensus != null && useDirectoryCaches) {
            // Try up to MAX_TRIES random ORs,
            // but don't try more than the number of running, valid, directory routers
            // (because this is random, some may be tried twice, and some may be skipped)
            int dirRouterCount = getORsWithFlag("V2Dir,Running,Valid").size();
            int dirTriesLimit = Math.min(dirRouterCount, MAX_TRIES);

            int i;
            for (i = 0; i < dirTriesLimit; i++) {
                // The V2Dir flag includes both authorities and directory caches
                // These typically makes up around 60% of routers
                // We could filter out authorities, but they make up less than 1% of the directories

                // Get a list of running, valid, directory routers, excluding bad exits
                // Typically, 80% of routers are running, and almost all are valid
                OnionRouter dir = getRandomORWithFlag("V2Dir,Running,Valid");

                System.out.println("Connecting to " + directoryType + " " + dir.name);
                try {
                    return connectToDirectoryStream(dir.ip, dir.dirport, path);
                } catch (IOException e) {
                    System.out.println("Failed to get " + path + " from " + directoryType + " "
                            + dir.ip + ":" + String.valueOf(dir.dirport));
                    continue;
                }
            }
        }

        directoryType = "authority";
        int authTriesLimit = Math.min(authorities.length, MAX_TRIES);

        // Try up to MAX_TRIES random authorities,
        // but don't try more than the number of listed authorities
        // (because this is random, some may be tried twice, and some may be skipped)

        int tries;
        for (tries = 0; tries < authTriesLimit; tries++) {

            int i = TorCrypto.rnd.nextInt(authorities.length);
            String auth = authorities[i];
            String sp[] = auth.split(" ");
            String ipp[] = sp[3].split(":");
            System.out.println("Connecting to " + directoryType + " " + sp[0]);
            try {
                return connectToDirectoryStream(ipp[0], ipp[1], path);
            } catch (IOException e) {
               System.out.println("Failed to get " + path + " from " + directoryType + " " + sp[0]);
               continue;
            }
        }

        throw new RuntimeException("Can't get " + path + " after " + String.valueOf(MAX_TRIES) + " tries.");
    }

    private InputStream connectToDirectoryStream(InetAddress address, int port, String path) throws IOException {
        return connectToDirectoryStream(address.getHostAddress(), String.valueOf(port), path);
    }

    private InputStream connectToDirectoryStream(String address, String port, String path) throws IOException {
        URL url = new URL("http://"+address+":"+port+path);

        // try the compressed version first, and transparently inflate it
        if (!path.endsWith(".z")) {
            try {
                URL zurl = new URL("http://" + address + ":" + port + path + ".z");
                System.out.println("Downloading: " + zurl.toString());
                InflaterInputStream infl = new InflaterInputStream(zurl.openStream());
                return infl;
            } catch (IOException e) {
                System.out.println("Transparent download of compressed stream failed, falling back to uncompressed."
                        + " Exception: " + e.toString());
            }
        }

        System.out.println("Downloading: " + url.toString());
        InputStream in = url.openStream();
        return in;
    }

    private boolean fetchConsensus() {
        try {
            //URL conurl = new URL("http://" + ip + ":" + dirport + "/tor/status-vote/current/consensus.z");
            InputStream connStream = getDirectoryStream("/tor/status-vote/current/consensus.z");

            BufferedReader in = new BufferedReader(new InputStreamReader(new InflaterInputStream(connStream)));
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

    /***
     * Return a consensus, populating it if needed
     *
     * @return populated Consensus
     */
    public static Consensus getConsensus() throws RuntimeException {
        // Default: don't retrieve an updated consensus, and don't return a new consensus object
        return getConsensus(false, false);
    }

    /***
     * Return an updated, new consensus, leaving existing consensus references as-is;
     * or return the existing consensus object with existing data
     *
     * @param retrieveUpdatedConsensus return a new, updated consensus
     * @return populated Consensus
     */
    public static Consensus getConsensus(Boolean retrieveUpdatedConsensus) throws RuntimeException {
        return getConsensus(retrieveUpdatedConsensus, retrieveUpdatedConsensus);
    }

    /***
     * Return an updated, new consensus, leaving existing consensus references as-is;
     * or return the existing consensus object with existing data
     *
     * @param retrieveUpdatedConsensus update the consensus before returning it
     * @param returnNewConsensus return a new consensus object, rather than the existing one.
     *                           returnNewConsensus implies retrieveUpdatedConsensus.
     * @return populated Consensus
     */
    public static Consensus getConsensus(Boolean retrieveUpdatedConsensus, Boolean returnNewConsensus) throws RuntimeException {
        // If returnNewConsensus is false, we call fetchConsensus() on the current consensus object (if it exists)
        // This updates the data in existing consensus references (which could cause unexpected results)
        if (consensus == null || retrieveUpdatedConsensus || returnNewConsensus) {
            try {
                if (consensus == null || returnNewConsensus) {
                    consensus = new Consensus();
                } else {
                    Boolean updateSucceeded = consensus.fetchConsensus();
                    if (!updateSucceeded) {
                        // Is it better to fail to update, or fail to keep the same consensus object?
                        // We update, even if it means creating a new object
                        System.out.println("getConsensus: fetchConsensus failed, returning new Consensus object");
                        consensus = new Consensus();
                    }
                }
            } catch (RuntimeException e) {
                // Should we add "failed to get consensus" to this exception?
                throw e;
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

    /***
     * Return the routers with the supplied flag(s), excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flag the desired flag(s) (case-sensitive). Multiple flags should be supplied in a comma-separated list.
     * @return a TreeMap of each router with the specified flag(s), indexed by identityhash
     */
    public TreeMap<String,OnionRouter> getORsWithFlag(String flag) {
        return getORsWithFlag(flag.split(","), true);
    }

    /***
     * Return the routers with all of the supplied flags, excluding bad exits
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flags the desired flags (case-sensitive)
     * @return a TreeMap of each router with the specified flags, indexed by identityhash
     */
    public TreeMap<String,OnionRouter> getORsWithFlag(String[] flags) {
        return getORsWithFlag(flags, true);
    }

    /***
     * Return the routers with all of the supplied flags, optionally excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     * Because OnionRouter.acceptsIPv4ExitPort is an expensive operation, we perform it in the getRandom*() functions.
     *
     * @param flags the desired flags (case-sensitive)
     * @param excludeBadExits exclude routers with the BadExit flags (these are considered unreliable for some purposes)
     * @return a TreeMap of each router with the specified flags, indexed by identityhash
     */
    public TreeMap<String,OnionRouter> getORsWithFlag(String[] flags, Boolean excludeBadExits) {
        TreeMap<String,OnionRouter> map = new TreeMap<>();
        for (OnionRouter r : routers.values()) {
            if(r.flags.containsAll(Arrays.asList(flags))
                    // either we're including (not excluding) bad exits, or we filter out routers with the bad exit flag
                    && (!excludeBadExits || !r.flags.contains("BadExit"))) {
                map.put(r.identityhash, r);
            }
        }
        return map;
    }


    /***
     * Return a (cryptographically) random router with the supplied flag(s), excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flag the desired flag(s) (case-sensitive). Multiple flags should be supplied in a comma-separated list.
     * @return a random router with the specified flag(s)
     */
    public OnionRouter getRandomORWithFlag(String flag) {
        return getRandomORWithFlag(flag.split(","), 0, true);
    }

    /***
     * Return a (cryptographically) random router with all of the supplied flags, excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flags the desired flags (case-sensitive)
     * @return a random router with the specified flags
     */
    public OnionRouter getRandomORWithFlag(String[] flags) {
        return getRandomORWithFlag(flags, 0, true);
    }

    /***
     * Return the routers with all of the supplied flags and the specified exitPort, excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flags the desired flags (case-sensitive)
     * @param exitPort the desired exit port in the router's exit policy (or 0 to ignore exit policies)
     * @return a random router with the specified flags
     */
    public OnionRouter getRandomORWithFlag(String[] flags, int exitPort) {
        return getRandomORWithFlag(flags, exitPort, true);
    }

    /***
     * Return the routers with all of the supplied flags and the specified exitPort, optonally excluding bad exits.
     * See https://consensus-health.torproject.org for a list of known flags.
     *
     * @param flags the desired flags (case-sensitive)
     * @param exitPort the desired exit port in the router's exit policy (or 0 to ignore exit policies)
     * @param excludeBadExits exclude routers with the BadExit flags (these are considered unreliable for some purposes)
     * @return a random router with the specified flags
     */
    public OnionRouter getRandomORWithFlag(String[] flags, int exitPort, Boolean excludeBadExits) {
        TreeMap<String, OnionRouter> map = getORsWithFlag(flags, excludeBadExits);
        OnionRouter ors[] = map.values().toArray(new OnionRouter[map.size()]);

        int idx = TorCrypto.rnd.nextInt(ors.length);

        // ignore exitPort 0
        if (exitPort != 0) {

            Boolean acceptsExitPort = ors[idx].acceptsIPv4ExitPort(exitPort);

            // iterate through the routers until we find one that accepts the desired exitPort
            while (!acceptsExitPort) {
                idx = TorCrypto.rnd.nextInt(ors.length);
                acceptsExitPort = ors[idx].acceptsIPv4ExitPort(exitPort);
            }

        }

        return ors[idx];
    }

    public String getRouterDescriptor(String hash) throws IOException {
        return IOUtils.toString(getDirectoryStream("/tor/server/fp/"+hash));
    }
}
