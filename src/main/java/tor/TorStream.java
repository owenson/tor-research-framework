package tor;

import tor.util.ByteFifo;

public class TorStream {

	int streamId;
	TorCircuit circ;
	
	ByteFifo recv = new ByteFifo(4096);
	ByteFifo send = new ByteFifo(4096);
	TorStreamListener listener;
	
	public TorStream(int streamId, TorCircuit circ, TorStreamListener list) {
		this.streamId = streamId;
		this.circ = circ;
		listener = list;
	}

	/**
	 * Get received data from this stream (e.g. data received from remote end)
	 * 
	 * @param bytes How many bytes? -1 for max.
	 * 
	 * @return Received bytes
	 */
	public byte[] recv(int bytes) {
		return recv.get(bytes);
	}

	
	/**
	 * Send bytes down this stream
	 * 
	 * @param b Bytes to send
	 */
	public void send(byte b[]) {
		send.put(b);
		circ.streamsSending.add(this); // add self to send queue
	}
	
	/**
	 * Internal function - used to receive bytes to send
	 * 
	 * @param bytes count (-1 for max)
	 * @return
	 */
	protected byte[] _getToSend(int bytes) {
		return send.get(bytes);
	}
	
	/**
	 * Internal function. Used to add received bytes to object.
	 * 
	 * @param b Bytes
	 */
	protected void _putRecved(byte b[]) {
		recv.put(b);
		if(listener != null)
			listener.dataArrived(this);
	}
	
	public void notifyDisconnect() {
		if(listener != null)
			listener.disconnected(this);
	}
	
	public void notifyConnect() {
		if(listener != null)
			listener.connected(this);
	}
	
	public interface TorStreamListener {
		public void dataArrived(TorStream s);
		public void connected(TorStream s);
		public void disconnected(TorStream s);
		public void failure(TorStream s);
	}
}
