package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;

public class CipherDecipher 
{
	static byte[] key = null;
	static Algorithm algorithm;
	
	private static void write_metadata(File origin_file, File destination_file, byte[] iv, short block_size, OperationModes operation_mode) throws Exception
	{
		FileOutputStream fOut = new FileOutputStream(destination_file);
		switch(operation_mode)
		{
		case CBC:
			fOut.write(0);
			break;
		case CTR:
			fOut.write(1);
			break;
		case ECB:
			fOut.write(2);
			break;		
		}
		switch(algorithm)
		{
		case AES128:
			fOut.write(0);
			break;
		case AES192:
			fOut.write(1);
			break;
		case AES256:
			fOut.write(2);
			break;
		case DES168:
			fOut.write(3);
			break;
		}
		if(operation_mode != OperationModes.ECB)
			fOut.write(iv);
    	int padding = (int) (origin_file.length()%block_size);
    	fOut.write(padding);
    	fOut.close();
	}
	
	public static void set_key(byte[] key)
	{
		CipherDecipher.key = key;
		switch(key.length)
		{
		case 16:
			CipherDecipher.algorithm = Algorithm.AES128;
			break;
		case 21:
			CipherDecipher.algorithm = Algorithm.DES168;
			break;
		case 24:
			CipherDecipher.algorithm = Algorithm.AES192;
			break;
		case 32:
			CipherDecipher.algorithm = Algorithm.AES256;
			break;
		}
	}
	
	public static void generate_key(Algorithm algorithm)
	{
		CipherDecipher.algorithm = algorithm;
		SecureRandom random = new SecureRandom();
		switch(algorithm)
		{
		case AES128:
			CipherDecipher.key = new byte[16];
			random.nextBytes(key);
			break;
		case AES192:
			CipherDecipher.key = new byte[24];
			random.nextBytes(key);
			break;
		case AES256:
			CipherDecipher.key = new byte[32];
			random.nextBytes(key);
			break;
		case DES168:
			CipherDecipher.key = new byte[21];
			random.nextBytes(key);
			break;
		}
	}

	public static void encipher(File origin_file, File destination_file, OperationModes operation_mode) throws Exception
	{
		SecureRandom random = new SecureRandom();
		FileInputStream fIn = new FileInputStream(origin_file);
		FileOutputStream fOut = new FileOutputStream(destination_file);
		short block_size = 16;
		switch(algorithm)
		{
		case AES128:
			block_size = 16;
			break;
		case AES192:
			block_size = 16;
			break;
		case AES256:
			block_size = 16;
			break;
		case DES168:
			block_size = 8;
			break;
		}
		byte[] origin = new byte[block_size];
		byte[] result = new byte[block_size];
		byte[] iv = null;
        if(operation_mode == OperationModes.CTR)
        {
			iv = new byte[block_size];
        	random.nextBytes(iv);
        }
        else if(operation_mode == OperationModes.CBC)
        {
        	result = new byte[block_size];
        	random.nextBytes(result);
        }
        CipherDecipher.write_metadata(origin_file, destination_file, operation_mode == OperationModes.CTR? iv : result, block_size, operation_mode);
		for(int i = 0; i < origin_file.length(); i += block_size)
	    {
	        int read_bytes = fIn.read(origin);
	        if(fIn.available() == 0)
	            for(int j = read_bytes - 1; j < block_size; j++)
	                origin[j] = (byte) random.nextInt(0xFF);
	        switch(operation_mode)
	        {
			case CBC:
				CBC(origin, result, key, block_size, true);
				break;
			case CTR:
				CTR(origin, iv, result, key, block_size, true);
				break;
			case ECB:
				cipher(origin, result, key, block_size, true);
				break;
			default:
				break;
	        
	        }
	        fOut.write(result);
	    }
	}
	
	private static void CBC(byte[] origin, byte[] result, byte[] key, short block_size, boolean encrypt)
	{
		byte[] aux = new byte[block_size];
	    if(encrypt)
	    {
	        XOR_Block(origin, result, aux, block_size);
	        cipher(aux, result, key, block_size, encrypt);
	    }
	    else
	    {
	        cipher(origin, result, key, block_size, encrypt);
	        XOR_Block(result, aux, result, block_size);
	        System.arraycopy(origin, 0, aux, 0, block_size);
	    }
	}

	private static void CTR(byte[] origin, byte[] IV, byte[] result, byte[] key, short block_size, boolean encrypt)
	{
	    cipher(IV, result, key, block_size, true);
	    XOR_Block(result, origin, result, block_size);
	    add(IV, (byte)1);
	}

	private static void add(byte[] array, byte number)
	{
	    for(int i = array.length - 1; i >= 0; i--)
	    {
	        byte aux = array[i];
	        array[i] = (byte) (array[i] + number);
	        if(aux == 0xFF && number != 0)
	            number = 1;
	        else break;
	    }
	}

	private static void XOR_Block(byte[] argument1,  byte[] argument2, byte[] result, int array_size)
	{
	    for(int i = 0; i < array_size; i++)
	        result[i] = (byte)(argument1[i] ^ argument2[i]);
	}

	private static void cipher(byte[] origin, byte[] result,  byte[] key, short block_size, boolean encrypt)
	{
		switch(algorithm)
		{
		case AES128:
			break;
		case AES192:
			break;
		case AES256:
			break;
		case DES168:
			break;
		}
	}
}
