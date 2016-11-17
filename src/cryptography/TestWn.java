package cryptography;

import java.io.File;
/*import java.security.SecureRandom;
import java.util.Random;*/

public class TestWn {

	public static void main(String[] args) throws Exception 
	{
		if(args.length != 3)
		{
			System.out.println("Modo de uso: <Algoritmo> <Modo de operacion> <Archivo.extension>");
			return;
		}
		Algorithm algorithm = Algorithm.valueOf(args[0]);
		OperationModes operation_mode = OperationModes.valueOf(args[1]);
		String[] filename = args[2].split("\\.");
		CipherDecipher cipher_decipher = new CipherDecipher(algorithm);
		File origin_file = new File(filename[0] + "." + filename[1]);
		File destination_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Cipher." + filename[1]);
		File recovered_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Decipher." + filename[1]);
		cipher_decipher.encipher(origin_file, destination_file, operation_mode);
		cipher_decipher.decipher(destination_file, recovered_file);
	}

}
