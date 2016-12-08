package cryptography;

import java.io.File;
/*import java.security.SecureRandom;
import java.util.Random;*/
import java.util.Random;

public class TestWn {

	public static void main(String[] args) throws Exception 
	{
		KeyRing key_ring = new KeyRing(new File("C:\\Users\\erwin\\Desktop\\keyring.key"));
		if(key_ring.key_ring.isEmpty())
		{
			Random rand = new Random();
			Curvas key_generator = new Curvas();
			CurvesKey[] keys = key_generator.generateKeyPair();
			CurvesKey public_key = keys[1], private_key = keys[0];
			key_ring.add_key_pair(public_key, private_key);
			key_ring.add_public_key("Manuel", key_generator.generateKeyPair()[1]);
			key_ring.add_public_key("Juan", key_generator.generateKeyPair()[1]);
			key_ring.add_public_key("Enrique", key_generator.generateKeyPair()[1]);
			key_ring.add_public_key("Mariana", key_generator.generateKeyPair()[1]);
			key_ring.add_public_key("Artemis", key_generator.generateKeyPair()[1]);
		}
		if(args.length != 6)
		{
			System.out.println("Modo de uso: <Algoritmo> <Modo de operacion> <Archivo.extension> <Llave> <-d|-e> <Nombre destino>");
			File keyfile = new File("C:\\Users\\erwin\\Desktop\\file.key");
			Curvas curva = new Curvas();
			CipherDecipher cipher = new CipherDecipher(keyfile, Algorithm.AES192, "Manuel", key_ring, curva);
			CipherDecipher decipher = new CipherDecipher(keyfile, key_ring, curva);
			return;
		}
		Curvas curva = new Curvas();
		Algorithm algorithm = Algorithm.valueOf(args[0]);
		OperationModes operation_mode = OperationModes.valueOf(args[1]);
		String[] filename = args[2].split("\\.");
		File keyfile = new File(args[3]);
		boolean encrypt = args[4].compareToIgnoreCase("-e") == 0;
		String nombre_destinatario = args[5];
		File origin_file = new File(filename[0] + "." + filename[1]);
		if(encrypt)
		{
			CipherDecipher cipher = new CipherDecipher(keyfile, algorithm, nombre_destinatario, key_ring, curva);
			File destination_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Cipher." + filename[1]);
			cipher.encipher(origin_file, destination_file, operation_mode);
		}
		else
		{
			CipherDecipher decipher = new CipherDecipher(keyfile, key_ring, curva);
			File recovered_file = new File(filename[0] + "_" + operation_mode + "_" + algorithm + "_Decipher." + filename[1]);
			decipher.decipher(origin_file, recovered_file);
		}
	}

}
