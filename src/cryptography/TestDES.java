package cryptography;

//Example using DES class

public class TestDES 
{
	
	public static void main(String[] args)
	{
	
	//Generate a key
	byte[] key1= new byte[8];
	byte[] key2= new byte[8];
	byte[] key3= new byte[8];
	for(int i = 0; i < 7; i++)
		key1[i] = (byte)i;
	for(int i = 0; i < 7; i++)
		key2[i] = (byte) (i+7);
	for(int i = 0; i < 7; i++)
		key3[i] = (byte) (i+14);
	DES first=new DES(key1);
	DES second=new DES(key2);
	DES third=new DES(key3);
	//Generate key_set

	byte[] origin={ 0,   0,   0,  13,  73,  72,  68,  82};
	
	for (int i=0; i<8; i++) System.out.print((byte)origin[i]+", ");
		System.out.println();
	
	//Encrypt block of 8 bytes
	byte[] aux1 = new byte[8];//[-118, -27, 90, -3, 52, -40, -81, -90]
	byte[] aux2 = new byte[8];//[-82, -25, -54, 100, -29, 11, -122, -63]
	byte[] result= new byte[8];//[-107, -99, -38, -47, -24, -22, 12, -12]
	first.process_message(origin, aux1, 1);
	second.process_message(aux1, aux2, 0);
	third.process_message(aux2, result, 1);
	
	for (int i=0; i<8; i++) System.out.print((byte)result[i]+", ");
		System.out.println();
		
	//Decrypt block of 8 bytes
	byte[] result1= new byte[8];//[0, 0, 0, 13, 73, 72, 68, 82]
	aux1 = new byte[8];//[-82, -25, -54, 100, -29, 11, -122, -63]
	aux2 = new byte[8];//[-118, -27, 90, -3, 52, -40, -81, -90]
	third.process_message(result, aux1, 0);
	second.process_message(aux1, aux2, 1);
	first.process_message(aux2, result1, 0);
		
	for (int i=0; i<8; i++) System.out.print((byte)result1[i]+", ");
		System.out.println();
	System.out.print("F");
	
	}
}
