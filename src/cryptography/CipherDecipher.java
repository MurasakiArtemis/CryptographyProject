package cryptography;

import java.security.SecureRandom;

public class CipherDecipher 
{
	public static byte[] generate_key(Algorithm algorithm)
	{
		SecureRandom random = new SecureRandom();
		byte[] array = null;
		switch(algorithm)
		{
		case AES128:
			array = new byte[16];
			random.nextBytes(array);
			break;
		case AES192:
			array = new byte[24];
			random.nextBytes(array);
			break;
		case AES256:
			array = new byte[32];
			random.nextBytes(array);
			break;
		case DES168:
			array = new byte[24];
			random.nextBytes(array);
			break;
		}
		return array;
	}
}
