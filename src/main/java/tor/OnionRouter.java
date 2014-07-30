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
import tor.util.TorDocumentParser;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.HashSet;

public class OnionRouter {
    String name;
<<<<<<< HEAD
    InetAddress ip;
    int orport;
    int dirport;
    PublicKey pubKey = null;
    public String identityhash;
=======
	InetAddress ip;
	int orport;
	int dirport;
	PublicKey pubKey = null;
	public String identityhash;
>>>>>>> d9afd0dcb89e770f34465680c2eebbe3ac0aa54a
    public HashSet<String> flags = new HashSet<>();
    public byte[] pubKeyraw;
    public String consensusIPv4ExitPortSummary = null;
    public String[] descriptorIPv4ExitPolicy = null;
    public String[] parsedIPv4ExitPortList = null;

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
        // return true to short-circuit potentially expensive checks that will never succeed, through the entire router list
        if (exitPort == 0)
            return true;
        else if (exitPort < 0 || exitPort > 65535)
            return true;

<<<<<<< HEAD
        if (parsedIPv4ExitPortList == null) {
=======
<<<<<<< HEAD
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
=======
        if (parsedIPv4ExitPortList == null) {
>>>>>>> d493d464e63ffc6acc2d280445119fcf5d6db270
>>>>>>> d9afd0dcb89e770f34465680c2eebbe3ac0aa54a

            // if we don't have the p line from the consensus, download the entire router descriptor
            if (consensusIPv4ExitPortSummary == null && descriptorIPv4ExitPolicy == null) {
                try {
                    TorDocumentParser rdr = new TorDocumentParser(Consensus.getConsensus().getRouterDescriptor(identityhash));
                    descriptorIPv4ExitPolicy = rdr.getArrayItem(TorDocumentParser.IPv4PolicyKey);
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

            // The algorithm for parsing exit policies is complex,
            // and even tor (C) sometimes connects to exits that are not suitable
            // (e.g. because the remote IP isn't known, and therefore tor only performs an approximate coverage check,
            // or because tor is using the port summary from the consensus).
            // See https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt for the gory details

            // use p line in consensus if available
            // https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt
            // "p" SP ("accept" / "reject") SP PortList NL
            // [At most once.]
            // PortList = PortOrRange
            // PortList = PortList "," PortOrRange
            // PortOrRange = INT "-" INT / INT
            // A list of those ports that this router supports (if 'accept')
            // or does not support (if 'reject') for exit to "most addresses".

            //System.out.println("acceptsIPv4ExitPort: checking for exit port " + String.valueOf(exitPort) + " in: "
            //        + consensusIPv4ExitPortSummary);

            // Pre-process the exit summary into an array of:
            // ("accept" / "reject") SP PortOrRange
            if (consensusIPv4ExitPortSummary != null) {
                String[] lineSplit = consensusIPv4ExitPortSummary.split(" ");
                String acceptOrReject = lineSplit[0];
                String[] portListSplit = lineSplit[1].split(",");
                parsedIPv4ExitPortList = new String[portListSplit.length];

                int i = 0;
                for (String portOrRange : portListSplit) {
                    parsedIPv4ExitPortList[i] = acceptOrReject + " " + portOrRange;
                    i++;
                }
            }

            //System.out.println("acceptsIPv4ExitPort: checking for exit port " + String.valueOf(exitPort) + " in:\n"
            //        + String.join("\n", descriptorIPv4ExitPolicy));

            // We implement a simplified version which ignores IP addresses (skipping any that aren't "*")
            // Each line of the policy consists of:
            // ("accept" / "reject") SP IP ":" PortOrRange NL

            // Pre-process the exit policy into an array of:
            // ("accept" / "reject") SP PortOrRange

            Boolean isParsedListEmpty = false;

            if (parsedIPv4ExitPortList == null)
                isParsedListEmpty = true;
            else if (parsedIPv4ExitPortList.length == 0)
                isParsedListEmpty = true;

            if (isParsedListEmpty && descriptorIPv4ExitPolicy != null) {
                // allow an extra item for the final "accept *"
                parsedIPv4ExitPortList = new String[descriptorIPv4ExitPolicy.length + 1];

                int i = 0;
                for (String policy : descriptorIPv4ExitPolicy) {
                    String[] lineSplit = policy.split(" ");
                    String acceptOrReject = lineSplit[0];
                    String[] ipPortSplit = lineSplit[1].split(":");
                    String portOrRange = ipPortSplit[1];

                    // only process lines that apply to all IPs
                    if (ipPortSplit.equals("*")) {

                        // replace * ports with the full numeric port range
                        if (portOrRange.equals("*")) {
                            portOrRange = "1-65535";
                        }

                        parsedIPv4ExitPortList[i] = acceptOrReject + " " + portOrRange;
                        i++;
                    }
                }

                // "if no rule matches, the address will be accepted"
                parsedIPv4ExitPortList[i] = "accept 1-65535";
                i++;
            }
        }

        // now compare the desired port to the parsed port policy
        // The parsed policy is an ordered array of:
        // ("accept" / "reject") SP PortOrRange
        if (parsedIPv4ExitPortList != null) {

            for (String portPolicy : parsedIPv4ExitPortList) {

                // because we skip some lines when parsing descriptors, some lines may be empty
                if (portPolicy != null) {

                    String[] lineSplit = portPolicy.split(" ");
                    Boolean accepted = lineSplit[0].equals("accept");
                    String portRange = lineSplit[1];
                    String[] portSplit = portRange.split("-");

                    if (portSplit.length == 1) {
                        // duplicate the single port to make a range
                        String port = portSplit[0];

                        portSplit = new String[2];
                        portSplit[0] = port;
                        portSplit[1] = port;
                    }

                    // portSplit is now a port range
                    try {

                        int lowPort = Integer.parseInt(portSplit[0]);
                        int highPort = Integer.parseInt(portSplit[1]);

                        if (exitPort >= lowPort && exitPort <= highPort)
                            // return the range match result
                            return accepted;
                        else
                            // no match, so check the next line
                            continue;

                    } catch (NumberFormatException e) {
                        // a line we don't understand - assume policy is too complex
                        System.out.println("acceptsIPv4ExitPort: failed to parse " + lineSplit[0]
                                + " port numbers in exit policy for: " + name
                                + ", assuming reject by: " + portPolicy);
                        return false;
                    }
                }
            }
        }

        // if no line matches the port,
        // either we've used a consensus summary that doesn't contain the port,
        // or we couldn't find both the consensus summary and the router descriptor
        return false;
    }

    @Override
    public String toString() {
        return "OnionRouter [name=" + name + ", ip=" + ip + ", orport="
                + orport + ", identityhash=" + identityhash + "]";
    }

}
