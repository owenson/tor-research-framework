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

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;

public class TorCrypto {
	public static SecureRandom rnd = new SecureRandom();
	public final static int KEY_LEN=16;
	public final static int DH_LEN=128; 
	public final static int DH_SEC_LEN=40;
	public final static int PK_ENC_LEN=128; 
	public final static int PK_PAD_LEN=42;
	public final static int HASH_LEN=20;
    public static BigInteger DH_G = new BigInteger("2");
    public static BigInteger DH_P = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");

    public TorCrypto() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException {
		
	}

	/**
	 * BigInteger to byte array, stripping leading zero if applicable (e.g. unsigned data only)
	 * 
	 * @param in BigInteger
	 * @return
	 */
	public static byte[] BNtoByte(BigInteger in) {
		byte[] intmp = in.toByteArray();
		if(intmp[0] != 0)
			return intmp;
		
		byte intmp2[] = new byte[intmp.length-1];
		System.arraycopy(intmp, 1, intmp2, 0, intmp2.length);
		return intmp2;
	}
	
	// add zero sign byte so always positive
	/**
	 * Converts byte array to BigInteger, adding zero sign byte to make unsigned.
	 * 
	 * @param in BigInteger
	 * @return
	 */
	public static BigInteger byteToBN(byte in[]) {
		byte tmp[] = new byte[in.length+1];
		tmp[0] = 0;
		System.arraycopy(in, 0, tmp, 1, in.length);
		return new BigInteger(tmp);
	}

    public static MessageDigest getSHA1() {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return md;
    }
	/**
	 * Tor Key derivation function
	 * 
	 * @param secret A secret
	 * @param length Length of key data to generate
	 * @return Key data
	 */
	public static byte[] torKDF(byte []secret, int length) {
		byte data[] = new byte[(int)Math.ceil(length / (double)HASH_LEN) * HASH_LEN];
		byte hashdata[] = new byte[secret.length + 1];
		
		assert secret.length == DH_LEN;  // checks if secret is length of diffie-hellman - might not be applicable in some cases
		
		//System.out.println("sec len " + secret.length);
		
		System.arraycopy(secret, 0, hashdata, 0, secret.length);
		
		for (int i=0; i<data.length/HASH_LEN; i++) {
			hashdata[secret.length] = (byte)i;
			MessageDigest md;
			try {
				md = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
			System.arraycopy(md.digest(hashdata), 0, data, i*HASH_LEN, HASH_LEN);
		}
		return data;
	}
	
	/**
	 * Tor Hybrid Encrypt function
	 * 
	 * @param in Data to encrypt
	 * @param pk Onion Router public key to encrypt to
	 * 
	 * @return Encrypted data
	 */
	public static byte[] hybridEncrypt(byte[] in, PublicKey pk)  {
		try {
			Cipher rsa = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
			rsa.init(Cipher.ENCRYPT_MODE, pk);
			if(in.length < PK_ENC_LEN-PK_PAD_LEN ) {
				return rsa.doFinal(in);
			} else {
				// prep key and IV
				byte []key = new byte[KEY_LEN];
				rnd.nextBytes(key);
				byte []iv = new byte [] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
				SecretKeySpec keysp = new SecretKeySpec(key, "AES");
				IvParameterSpec ivSpec = new IvParameterSpec(iv);
				
				// prepare m1
				byte m1a[] = Arrays.copyOfRange(in, 0, PK_ENC_LEN-PK_PAD_LEN-KEY_LEN);
				byte m1[] = ArrayUtils.addAll(key, m1a);
				byte rsaciphertext [] = rsa.doFinal( m1 );
				
				// prepare m2
				byte m2[] = Arrays.copyOfRange(in, m1a.length, in.length);
				Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
				aes.init(Cipher.ENCRYPT_MODE, keysp, ivSpec);
				byte aesciphertext [] = aes.doFinal( m2 );
				
				// merge
				return ArrayUtils.addAll(rsaciphertext, aesciphertext);
			}
		} catch (BadPaddingException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Parses a public key encoded as ASN.1
	 * 
	 * @param rsapublickey ASN.1 Encoded public key
	 * 
	 * @return PublicKey
	 */
	public static PublicKey asn1GetPublicKey(byte[] rsapublickey) {
		int blobsize = rsapublickey.length;
		DataInputStream dis = null;
		int jint = 0; // int to represent unsigned byte or unsigned short
		int datacount = 0;

		try {
			// --- Try to read the ANS.1 encoded RSAPublicKey blob -------------
			ByteArrayInputStream bis = new ByteArrayInputStream(rsapublickey);
			dis = new DataInputStream(bis);

			if (dis.readByte() != 0x30) // asn.1 encoded starts with 0x30
				return null;

			jint = dis.readUnsignedByte(); // asn.1 is 0x80 plus number of bytes
											// representing data count
			if (jint == 0x81)
				datacount = dis.readUnsignedByte(); // datalength is specified
													// in next byte.
			else if (jint == 0x82) // bytes count for any supported keysize
									// would be at most 2 bytes
				datacount = dis.readUnsignedShort(); // datalength is specified
														// in next 2 bytes
			else
				return null; // all supported publickey byte-sizes can be
								// specified in at most 2 bytes

			if ((jint - 0x80 + 2 + datacount) != blobsize) // sanity check for
															// correct number of
															// remaining bytes
				return null;

	//		System.out
		//			.println("\nRead outer sequence bytes; validated outer asn.1 consistency ");

			// ------- Next attempt to read Integer sequence for modulus ------
			if (dis.readUnsignedByte() != 0x02) // next byte read must be
												// Integer asn.1 specifier
				return null;
			jint = dis.readUnsignedByte(); // asn.1 is 0x80 plus number of bytes
											// representing data count
			if (jint == 0x81)
				datacount = dis.readUnsignedByte(); // datalength is specified
													// in next byte.
			else if (jint == 0x82) // bytes count for any supported keysize
									// would be at most 2 bytes
				datacount = dis.readUnsignedShort(); // datalength is specified
														// in next 2 bytes
			else
				return null; // all supported publickey modulus byte-sizes can
								// be specified in at most 2 bytes

			// ---- next bytes are big-endian ordered modulus -----
			byte[] modulus = new byte[datacount];
			int modbytes = dis.read(modulus);
			if (modbytes != datacount) // if we can read enought modulus bytes
										// ...
				return null;

			//System.out.println("Read modulus");

			// ------- Next attempt to read Integer sequence for public exponent
			// ------
			if (dis.readUnsignedByte() != 0x02) // next byte read must be
												// Integer asn.1 specifier
				return null;
			datacount = dis.readUnsignedByte(); // size of modulus is specified
												// in one byte
			byte[] exponent = new byte[datacount];
			int expbytes = dis.read(exponent);
			if (expbytes != datacount)
				return null;
			//System.out.println("Read exponent");

			// ----- Finally, create the PublicKey object from modulus and
			// public exponent --------
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(
					1, modulus), new BigInteger(1, exponent));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
			return pubKey;
		} catch (Exception exc) {
			return null;
		} finally {
			try {
				dis.close();
			} catch (Exception exc) {
				;
			}
		}
	}

}
