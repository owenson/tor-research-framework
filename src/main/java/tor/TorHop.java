package tor;

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
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TorHop {

	byte[] kh = new byte[TorCrypto.HASH_LEN], df = new byte[TorCrypto.HASH_LEN], db = new byte[TorCrypto.HASH_LEN];
	byte[] kf = new byte[TorCrypto.KEY_LEN], kb = new byte[TorCrypto.KEY_LEN];
	public MessageDigest df_md, db_md;
	Cipher encf, encb;
	OnionRouter router;
	
	/**
	 * Creates TorHop object taking derived key data and calculating keys
	 * 
	 * @param kdf Derived key data from created/extended cell
	 * @param _kh KH for verification of correct KDF
	 * @param _r Router which this hop represents
	 */
	public TorHop(byte kdf[], byte _kh[], OnionRouter _r) {
		router = _r;
		ByteBuffer buf = ByteBuffer.wrap(kdf);
		buf.get(kh);
		buf.get(df);
		buf.get(db);
		buf.get(kf);
		buf.get(kb);

		try {
			df_md = MessageDigest.getInstance("SHA-1");
			df_md.update(df);
            db_md = MessageDigest.getInstance("SHA-1");
            db_md.update(db);

			IvParameterSpec ivSpec = new IvParameterSpec(new byte [] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});	
			SecretKeySpec keysp = new SecretKeySpec(kf, "AES");
			encf = Cipher.getInstance("AES/CTR/NoPadding");
			encf.init(Cipher.ENCRYPT_MODE, keysp, ivSpec);
			
			keysp = new SecretKeySpec(kb, "AES");
			encb = Cipher.getInstance("AES/CTR/NoPadding");
			ivSpec = new IvParameterSpec(new byte [] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
			encb.init(Cipher.DECRYPT_MODE, keysp, ivSpec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException (e);
		}

		
		if(!Arrays.equals(_kh,  kh))
			throw new RuntimeException("hop key setup failed");
		
		System.out.println("Hop added " + router);
	}

    @Override
    public String toString() {
        return "TorHop{" +
                "router=" + router +
                '}';
    }

    public byte[] encrypt(byte[] in) {
		return encf.update(in);
	}
	
	protected byte[] decrypt(byte[] in) {
		return encb.update(in);
	}

}
