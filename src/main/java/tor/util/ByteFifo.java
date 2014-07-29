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
package tor.util;

import org.bouncycastle.util.Arrays;


public class ByteFifo {

	byte buffer [];
	int in = 0, out = 0;
    int count = 0;
	
	/*test code
	 * ByteFifo fifo = new ByteFifo(10);
	for(int i=0; i<5; i++) {
		fifo.put("hello".getBytes());
		System.out.println(new String(fifo.get(4)));
	}*/
	
	public ByteFifo(int capacity) {
		buffer = new byte[capacity];
	}

    public boolean isEmpty() {
        return in == out;
    }

	public synchronized void put(byte []toput) {
		for (byte b : toput) {
			buffer[in] = b;
			in = (in + 1) % buffer.length;
            count++;
			if(count >= buffer.length)
				throw new RuntimeException("buffer overflow");
		}
	}

    public int available() {
        return count;
    }

	// bytes = -1 for unlimited
	public synchronized byte[] get(int bytes) {
		byte buf[] = new byte[buffer.length];
		int cnt = 0;
		while(count>0 && (bytes == -1 || cnt<bytes)) {
			buf[cnt++] = buffer[out];
            count--;
			out = (out + 1) % buffer.length;
		}
		return Arrays.copyOfRange(buf, 0, cnt);
	}

}
