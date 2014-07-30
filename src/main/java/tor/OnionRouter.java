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
    public HashSet<String> flags = new HashSet<>();
    public byte[] pubKeyraw;
    public String[] IPv4ExitPolicy = null;

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

    public Boolean acceptsIPv4ExitPort(int exitPort) {

        // ignore an exitPort of 0, and invalid exitPorts
        if (exitPort == 0)
            return true;
        else if (exitPort < 0 || exitPort > 65535)
            return true;

        if (IPv4ExitPolicy == null) {
            try {
                // Do we need to download this separately, or does it come as part of the consensus?
                TorDocumentParser rdr = new TorDocumentParser(Consensus.getConsensus().getRouterDescriptor(identityhash));
                IPv4ExitPolicy = rdr.getArrayItem(TorDocumentParser.IPv4PolicyKey);
            } catch(IOException e) {
                System.out.println("acceptsIPv4ExitPort: failed to retrieve exit policy for: " + name
                        + ", assuming reject. Parsing router descriptor failed with IOException: " + e.toString());
                return false;
            } catch(RuntimeException e) {
                System.out.println("acceptsIPv4ExitPort: failed to retrieve exit policy for: " + name
                        + ", assuming reject. Retrieving consensus failed with RuntimeException: " + e.toString());
                return false;
            }
        }

        //System.out.println("acceptsIPv4ExitPort: checking for exit port " + String.valueOf(exitPort) + " in:\n"
        //        + String.join("\n", IPv4ExitPolicy));

        // The algorithm for parsing exit policies is complex,
        // and even tor (C) sometimes connects to exits that are not suitable
        // (e.g. because the remote IP isn't known, and therefore tor only performs an approximate coverage check)
        // See https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt for the gory details

        // We implement a simplified version which ignores IP addresses (assuming all for reject and none for accept)
        // Each line of the policy consists of:
        // accept/reject IP:Port[-Range]
        for (String policy : IPv4ExitPolicy) {
            String[] lineSplit = policy.split(" ");

            if (lineSplit.length != 2) {
                // a line we don't understand - assume policy is too complex
                System.out.println("acceptsIPv4ExitPort: failed to parse line in exit policy for: " + name
                        + ", assuming reject by: " + policy);
                return false;
            } else if (lineSplit[0].equals("accept")) {
                // exitpattern ::= addrspec ":" portspec
                String[] addressSplit = lineSplit[1].split(":");

                if (addressSplit.length != 2) {
                    // a line we don't understand - assume policy is too complex
                    System.out.println("acceptsIPv4ExitPort: failed to parse accept address in exit policy for: " + name
                            + ", assuming reject by: " + policy);
                    return false;
                } else {
                    // an ip followed by port range
                    String ip = addressSplit[0];
                    String portRange = addressSplit[1];

                    // check ip is "*", otherwise disregard line as not applying to all IPs

                    if (ip.equals("*")) {
                        //portspec ::= "*" | port | port "-" port
                        String[] portSplit = portRange.split("-");

                        if (portSplit.length == 0 || portSplit.length > 2) {
                            // a line we don't understand - assume policy is too complex
                            System.out.println("acceptsIPv4ExitPort: failed to parse accept port (range) in exit policy for: " + name
                                    + ", assuming reject by: " + policy);
                            return false;
                        } else if (portSplit.length == 1) {
                            // a single port

                            if (portSplit[0].equals("*"))
                                // accept all ports
                                return true;
                            else if (portSplit[0].equals(String.valueOf(exitPort)))
                                // accept exact match
                                return true;
                            else
                                // no match, so check the next line
                                continue;

                        } else /*if (portSplit.length == 2)*/ {
                            // a port range
                            try {

                                int lowPort = Integer.parseInt(portSplit[0]);
                                int highPort = Integer.parseInt(portSplit[1]);

                                if (exitPort >= lowPort && exitPort <= highPort)
                                    // accept range match
                                    return true;
                                else
                                    // no match, so check the next line
                                    continue;

                            } catch (NumberFormatException e) {
                                // a line we don't understand - assume policy is too complex
                                System.out.println("acceptsIPv4ExitPort: failed to parse accept port numbers in exit policy for: " + name
                                        + ", assuming reject by: " + policy);
                                return false;
                            }
                        }

                    } else {
                        // we haven't found an accept policy that applies to all IPs
                        // try the next policy
                        continue;
                    }
                }

            } else if (lineSplit[0].equals("reject")) {
                // this code repeats a lot of the "accept" code and could be refactored

                // exitpattern ::= addrspec ":" portspec
                String[] addressSplit = lineSplit[1].split(":");

                if (addressSplit.length != 2) {
                    // a line we don't understand - assume policy is too complex
                    System.out.println("acceptsIPv4ExitPort: failed to parse reject address in exit policy for: " + name
                            + ", assuming reject by: " + policy);
                    return false;
                } else {
                    // an ip followed by port range
                    String ip = addressSplit[0];
                    String portRange = addressSplit[1];

                    // check ip is "*", otherwise disregard line as not applying to all IPs
                    if (ip.equals("*")) {

                        //portspec ::= "*" | port | port "-" port
                        String[] portSplit = portRange.split("-");

                        if (portSplit.length == 0 || portSplit.length > 2) {
                            // a line we don't understand - assume policy is too complex
                            System.out.println("acceptsIPv4ExitPort: failed to parse reject port (range) in exit policy for: " + name
                                    + ", assuming reject by: " + policy);
                            return false;
                        } else if (portSplit.length == 1) {
                            // a single port

                            if (portSplit[0].equals("*")) {
                                // reject all ports
                                System.out.println("acceptsIPv4ExitPort: reject " + portSplit[0] + " in exit policy for: " + name
                                        + " in: " + policy);
                                return false;
                            } else if (portSplit[0].equals(String.valueOf(exitPort))) {
                                // reject exact match
                                System.out.println("acceptsIPv4ExitPort: reject " + portSplit[0] + " in exit policy for: " + name
                                        + " in: " + policy);
                                return false;
                            } else {
                                // no match, so check the next line
                                continue;
                            }

                        } else /*if (portSplit.length == 2)*/ {
                            // a port range
                            try {

                                int lowPort = Integer.parseInt(portSplit[0]);
                                int highPort = Integer.parseInt(portSplit[1]);

                                if (exitPort >= lowPort && exitPort <= highPort) {
                                    // reject range match
                                    System.out.println("acceptsIPv4ExitPort: reject "
                                            + portSplit[0] + "-" + portSplit[1] + " in exit policy for: " + name
                                            + " in: " + policy);
                                    return false;
                                } else {
                                    // no match, so check the next line
                                    continue;
                                }

                            } catch (NumberFormatException e) {
                                // a line we don't understand - assume policy is too complex
                                System.out.println("acceptsIPv4ExitPort: failed to parse reject port numbers in exit policy for: " + name
                                        + ", assuming reject by: " + policy);
                                return false;
                            }
                        }
                    }
                }

            } else {
                // not "accept" or "reject", assume further details of policy are too complex
                System.out.println("acceptsIPv4ExitPort: failed to parse accept/reject: (" + lineSplit[0]
                        + ") in exit policy for: " + name
                        + ", assuming reject by: " + policy);
                return false;
            }
        }

        // "if no rule matches, the address will be accepted"
        return true;
    }

	@Override
	public String toString() {
		return "OnionRouter [name=" + name + ", ip=" + ip + ", orport="
				+ orport + ", identityhash=" + identityhash + "]";
	}

}
