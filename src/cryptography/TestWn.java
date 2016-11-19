package cryptography;

import java.io.File;
/*import java.security.SecureRandom;
import java.util.Random;*/

public class TestWn {

	public static void main(String[] args) throws Exception 
	{
		if(args.length != 5)
		{
			System.out.println("Modo de uso: <Algoritmo> <Modo de operacion> <Archivo.extension> <Llave> <-d|-e>");
			return;
		}
		Algorithm algorithm = Algorithm.valueOf(args[0]);
		OperationModes operation_mode = OperationModes.valueOf(args[1]);
		String[] filename = args[2].split("\\.");
		File keyfile = new File(args[3]);
		boolean encrypt = args[4].compareToIgnoreCase("-e") == 0;
		File origin_file = new File(filename[0] + "." + filename[1]);
		if(encrypt)
		{
			CipherDecipher cipher = new CipherDecipher(keyfile, algorithm);
			File destination_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Cipher." + filename[1]);
			cipher.encipher(origin_file, destination_file, operation_mode);
		}
		else
		{
			CipherDecipher decipher = new CipherDecipher(keyfile);
			File recovered_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Decipher." + filename[1]);
			decipher.decipher(origin_file, recovered_file);
		}
	}

}
