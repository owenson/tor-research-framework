package tor.examples;

import tor.OnionRouter;
import tor.TorCircuit;
import tor.TorSocket;
import tor.TorStream;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class Main {

	public static void main(String[] args) throws IOException  {
		// TODO Auto-generated method stub
		
		
		OnionRouter guard = TorSocket.getConsensus().getRouterByName("tor26");
		TorSocket sock = new TorSocket(guard);
		
		// connected---------------
		TorCircuit circ = sock.createCircuit();
		circ.createRoute("gho,edwardsnowden1");
        circ.waitForState(TorCircuit.STATES.READY);

		System.out.println("READY!!");
		
		circ.createStream("ghowen.me", 80, new TorStream.TorStreamListener() {
			
			@Override
			public void failure(TorStream s) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void disconnected(TorStream s) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void dataArrived(TorStream s) {
                try {
                    System.out.println("data: "+new String(s.recv(-1,true)));
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
			
			@Override
			public void connected(TorStream s) {
				try {
					s.send("GET /ip HTTP/1.0\r\nHost: ghowen.me\r\n\r\n".getBytes("UTF-8"));
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
                    e.printStackTrace();
                }
                System.out.println("connected");
				
			}
		});
	}

}
