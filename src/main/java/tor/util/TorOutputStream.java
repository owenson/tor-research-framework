package tor.util;

import tor.TorStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Created by gho on 29/07/14.
 */
public class TorOutputStream extends OutputStream {
    private TorStream hostStream;

    public TorOutputStream(TorStream host) {
        hostStream = host;
    }

    @Override
    public void write(int i) throws IOException {
        hostStream.send(new byte[] {(byte)i});
    }

    @Override
    public void write(byte[] b) throws IOException {
        hostStream.send(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        hostStream.send(Arrays.copyOfRange(b, off, off+len));
    }


}
