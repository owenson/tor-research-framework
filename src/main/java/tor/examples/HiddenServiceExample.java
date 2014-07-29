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
package tor.examples;

import tor.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class HiddenServiceExample {

    public static void main(String[] args) throws IOException  {
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRouterByName("turtles"));

        // setup rendezvous circuit
        TorCircuit rendz = sock.createCircuit(true); //true means circuit calls should block until success
        rendz.createRoute("tor26");
        rendz.rendezvousSetup();

        final String ONION = "3g2upl4pq6kufc4m";

        // send introduce to introduction point and wait for rendezvous circuit to complete
        HiddenService.sendIntroduce(sock, ONION, rendz);

        // Connect to hidden service on port 80 and download a page
        TorStream hiddenServiceStream = rendz.createStream("", 80, null);
        hiddenServiceStream.waitForState(TorStream.STATES.READY);
        hiddenServiceStream.sendHTTPGETRequest("/", ONION+".onion");

        System.out.println("HS - fetching index.html...");

        BufferedReader rdr = new BufferedReader(new InputStreamReader(hiddenServiceStream.getInputStream()));

        String line;
        while ((line=rdr.readLine())!=null)
            System.out.println(line);



    }

}
