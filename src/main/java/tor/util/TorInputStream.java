package tor.util;

import tor.TorStream;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by gho on 29/07/14.
 */
public class TorInputStream extends InputStream {

    TorStream hostStream;
    public TorInputStream(TorStream st) {
        hostStream = st;
    }

    @Override
    public int available() throws IOException {
        return hostStream.recvBuffer.available();
    }

    @Override
    public long skip(long n) throws IOException {
        return hostStream.recv(new byte[(int)n], true);
    }

    @Override
    public int read() throws IOException {
        byte bytes[] = new byte[1];
        int received = hostStream.recv(bytes, true);

        return bytes[0];
    }

    @Override
    public int read(byte[] b) throws IOException {
        return hostStream.recv(b, true);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        byte buf[] = new byte[len];
        int received = hostStream.recv(buf, true);
        if(received==-1)
            return -1;
        System.arraycopy(buf, 0, b, off, received);
        return received;
    }
}
