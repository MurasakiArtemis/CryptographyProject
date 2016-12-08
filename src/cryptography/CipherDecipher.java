package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

public class CipherDecipher 
{
	private byte[] key = null;
	private Algorithm algorithm;
	private short block_size;
	private DES firstDES;
	private DES secondDES;
	private DES thirdDES;
	private AES aes;
	//Curvas.descifrar() recibe un archivo origen y regresa un arreglo bytes
	//Curvas.cifrar() recibe un arreglo bytes y un archivo destino
	//Lectura del archivo para descifrar
	public CipherDecipher(File file, KeyRing key_ring, Curvas decipher) throws Exception
	{
		/*try(ObjectInputStream fIn = new ObjectInputStream(new FileInputStream(file)))
		{
			//Descifrar llave con la clave privada
			for(int i = 0; fIn.available() != 0; i += 2)
			{
				PuntoCC puntocc_fragmento = (PuntoCC) fIn.readObject();
				short key_fragment = (short) decipher.descifrado(puntocc_fragmento, key_ring.key_ring.get("self_private"));
				key[i] = (byte)(key_fragment & 0xff);
				key[i + 1] = (byte)((key_fragment >> 8) & 0xff);
			}
		}*///Change files in order to use temporary files
		File temp = File.createTempFile("prefix", "suffix");
		decipher.descifrado(file, temp, key_ring.key_ring.get("self_private"));
		FileInputStream fIn = new FileInputStream(temp);
		byte[] key = new byte[(int) temp.length()];
		fIn.read(key);
		fIn.close();
		if(key.length == 22)
		{
			byte[] new_key = new byte[21];
			System.arraycopy(key, 0, new_key, 0, 21);
			key = new_key;
		}
		set_key(key);
		configure_algorithm();
		set_block_size();
	}
	
	//Creacion del archivo para cifrar//file is not used, use it to store the ciphered key 
	public CipherDecipher(File file, Algorithm algorithm, String nombre_destinatario, KeyRing key_ring, Curvas cipher) throws Exception
	{
		generate_key(algorithm);
		configure_algorithm();
		set_block_size();
		File temp = File.createTempFile("prefix", "suffix");
		FileOutputStream fOut = new FileOutputStream(temp);
		fOut.write(key);
		fOut.close();
		cipher.cifrado(temp, file, key_ring.key_ring.get(nombre_destinatario));
		/*try(ObjectOutputStream fOut = new ObjectOutputStream(new FileOutputStream(file)))
		{
			//Cifrar llave con la clave publica del receptor
			for(int i = 0; i < key.length; i += 2)
			{
				short key_fragment = (short) (key[i] & (key[i+1] << 8));
				CurvesKey key = key_ring.key_ring.get(nombre_destinatario);
				PuntoCC puntocc_fragmento = cipher.cifrado(key_fragment, key);
				fOut.writeObject(puntocc_fragmento);
			}
		}*/
	}
	
	//Ajuste de la llave para descifrar
	public CipherDecipher(byte[] key)
	{
		set_key(key);
		configure_algorithm();
		set_block_size();
	}
	
	//Creacion de la llave para cifrar
	public CipherDecipher(Algorithm algorithm)
	{
		generate_key(algorithm);
		configure_algorithm();
		set_block_size();
	}
	
	public void encipher(File origin_file, File destination_file, OperationModes operation_mode) throws Exception
	{
		this.process_request(origin_file, destination_file, operation_mode, true);
	}
	
	public void decipher(File origin_file, File destination_file) throws Exception
	{
		this.process_request(origin_file, destination_file, null, false);    	
	}
	
	private void write_metadata(File origin_file, File destination_file, byte[] iv, short block_size, OperationModes operation_mode, int padding) throws Exception
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
		if(operation_mode != OperationModes.ECB)
			fOut.write(iv);
    	fOut.write(padding);
    	fOut.close();
	}
	
	private void configure_algorithm()
	{
		if(algorithm == Algorithm.DES168)
		{
			byte[] key1 = new byte[8];
			byte[] key2 = new byte[8];
			byte[] key3 = new byte[8];
			System.arraycopy(key, 0, key1, 0, 7);
			System.arraycopy(key, 7, key2, 0, 7);
			System.arraycopy(key, 14, key3, 0, 7);
			firstDES = new DES(key1);
			secondDES = new DES(key2);
			thirdDES = new DES(key3);
		}
		else
		{
			int keysize = 128;
			switch(algorithm)
			{
			case AES128:
				keysize = 128;
				break;
			case AES192:
				keysize = 192;
				break;
			case AES256:
				keysize = 256;
				break;
			default:
				break;
			}
			aes = new AES(key, keysize);
		}
	}
	
	private void set_key(byte[] key)
	{
		this.key = key;
		switch(key.length)
		{
		case 16:
			this.algorithm = Algorithm.AES128;
			break;
		case 21:
			this.algorithm = Algorithm.DES168;
			break;
		case 24:
			this.algorithm = Algorithm.AES192;
			break;
		case 32:
			this.algorithm = Algorithm.AES256;
			break;
		}
	}
	
	private void generate_key(Algorithm algorithm)
	{
		this.algorithm = algorithm;
		SecureRandom random = new SecureRandom();
		switch(algorithm)
		{
		case AES128:
			this.key = new byte[16];
			random.nextBytes(key);
			break;
		case AES192:
			this.key = new byte[24];
			random.nextBytes(key);
			break;
		case AES256:
			this.key = new byte[32];
			random.nextBytes(key);
			break;
		case DES168:
			this.key = new byte[21];
			random.nextBytes(key);
			break;
		}
	}

	private void set_block_size()
	{
		block_size = 16;
		switch(algorithm)
		{
		case AES128:
		case AES192:
		case AES256:
			block_size = 16;
			break;
		case DES168:
			block_size = 8;
			break;
		}
	}
	
	private void process_request(File origin_file, File destination_file, OperationModes operation_mode, boolean encrypt) throws Exception
	{
		SecureRandom random = new SecureRandom();
		FileInputStream fIn = new FileInputStream(origin_file);
		byte[] origin = new byte[block_size];
		byte[] result = new byte[block_size];
		byte[] iv = new byte[block_size];
		byte padding;
		if(encrypt)
		{
	        if(operation_mode == OperationModes.CTR)
	        {
	        	random.nextBytes(iv);
	        }
	        else if(operation_mode == OperationModes.CBC)
	        {
	        	random.nextBytes(result);
	        }
	        padding = (byte) (block_size - (origin_file.length()%block_size));
	        this.write_metadata(origin_file, destination_file, operation_mode == OperationModes.CTR? iv : result, block_size, operation_mode, padding);
		}
		else
		{
			//Extract information from the enciphered file
	        int readValue = fIn.read();
	        switch(readValue)
	        {
	        case 0:
	        	operation_mode = OperationModes.CBC;
	        	break;
	        case 1:
	        	operation_mode = OperationModes.CTR;
	        	break;
	        case 2:
	        	operation_mode = OperationModes.ECB;
	        	break;
	        }
	        if(operation_mode != OperationModes.ECB)
				fIn.read(iv);
	    	padding = (byte) fIn.read();
			//Finished extraction
		}
		FileOutputStream fOut;
		if(encrypt)
			fOut = new FileOutputStream(destination_file, true);
		else
			fOut = new FileOutputStream(destination_file);
		//for(int i = 0; i < origin_file.length(); i += block_size)
		while(fIn.available() != 0)
	    {
			int read_bytes = fIn.read(origin);
			if(encrypt)
			{
		        if(fIn.available() == 0)
		            for(int j = read_bytes; j < block_size; j++)
		                origin[j] = (byte) random.nextInt(0xFF);
			}
	        switch(operation_mode)
	        {
			case CBC:
				CBC(origin, iv, result, block_size, encrypt);
				break;
			case CTR:
				CTR(origin, iv, result, block_size, encrypt);
				break;
			case ECB:
				cipher(origin, result, block_size, encrypt);
				break;
			default:
				break;
	        
	        }
	        if(encrypt)
	        	fOut.write(result);
	        else if(fIn.available() > 0)
	        	fOut.write(result);
	        else
	        	fOut.write(result, 0, block_size - padding);
	    }
		fIn.close(); fOut.close();
	}
	
	private void CBC(byte[] origin, byte[] aux, byte[] result, short block_size, boolean encrypt)
	{
	    if(encrypt)
	    {
	    	aux = new byte[block_size];
	        XOR_Block(origin, result, aux, block_size);
	        cipher(aux, result, block_size, encrypt);
	    }
	    else
	    {
	        cipher(origin, result, block_size, encrypt);
	        XOR_Block(result, aux, result, block_size);
	        System.arraycopy(origin, 0, aux, 0, block_size);
	    }
	}

	private void CTR(byte[] origin, byte[] IV, byte[] result, short block_size, boolean encrypt)
	{
	    cipher(IV, result, block_size, true);
	    XOR_Block(result, origin, result, block_size);
	    add(IV, (byte)1);
	}

	private void add(byte[] array, byte number)
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

	private void XOR_Block(byte[] argument1,  byte[] argument2, byte[] result, int array_size)
	{
	    for(int i = 0; i < array_size; i++)
	        result[i] = (byte)(argument1[i] ^ argument2[i]);
	}

	private void cipher(byte[] origin, byte[] result, short block_size, boolean encrypt)
	{
		switch(algorithm)
		{
		case DES168:
			byte[] aux1 = new byte[block_size];
			byte[] aux2 = new byte[block_size];
			if(encrypt)
			{
				firstDES.process_message(origin, aux1, 1);
				secondDES.process_message(aux1, aux2, 0);
				thirdDES.process_message(aux2, result, 1);
			}
			else
			{
				thirdDES.process_message(origin, aux1, 0);
				secondDES.process_message(aux1, aux2, 1);
				firstDES.process_message(aux2, result, 0);
			}
			break;
		default:
			if(encrypt)
				aes.aes_encrypt(origin, result);
			else
				aes.aes_decrypt(origin, result);
		}
	}
}
