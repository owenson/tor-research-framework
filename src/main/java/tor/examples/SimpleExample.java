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

import tor.Consensus;
import tor.TorCircuit;
import tor.TorSocket;
import tor.TorStream;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Created by gho on 26/07/14.
 */
public class SimpleExample {
    public static void main(String[] args) throws IOException {
        Consensus con = Consensus.getConsensus();
        TorSocket sock = new TorSocket(con.getRouterByName("turtles"));
        TorCircuit circ = sock.createCircuit(true);

        // use createRoute as below, or you can use create() followed by extend() manually
        //circ.create();
        //circ.extend(con.getRandomORWithFlag("Exit"));
        circ.createRoute("Snowden4ever,abbie");

        TorStream stream = circ.createStream("ghowen.me", 80, null);
        stream.waitForState(TorStream.STATES.READY);

        System.out.println("Connected to remote host through Tor");
        stream.sendHTTPGETRequest("/ip", "ghowen.me");

        BufferedReader rdr = new BufferedReader(new InputStreamReader(stream.getInputStream()));

        String line;
        while ((line = rdr.readLine()) != null)
            System.out.println(line);
    }
}
