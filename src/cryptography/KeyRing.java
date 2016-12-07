package cryptography;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;

public class KeyRing 
{
	File storage;
	public HashMap<String, CurvesKey> key_ring;
	
	public KeyRing(File storage)
	{
		this.storage = storage;
		if(storage.length() == 0 || storage.isDirectory())
			this.key_ring = new HashMap<>();
		else
		{
			try(ObjectInputStream ois = new ObjectInputStream(new FileInputStream(storage)))
			{
				this.key_ring = (HashMap<String, CurvesKey>) ois.readObject();
			} catch (IOException | ClassNotFoundException e) 
			{
				System.out.println(e.getMessage());
			}
		}
	}
	
	//Agrega la llave especificada al llavero
	public void add_public_key(String owner, CurvesKey key) throws IOException
	{
		key_ring.put(owner, key);
		save_key_ring();
	}
	
	//Elimina el archivo 
	public void delete_public_key(String owner) throws IOException
	{
		key_ring.remove(owner);
		save_key_ring();
	}
	
	//Agrega el par de llaves del usuario
	public void add_key_pair(CurvesKey public_key, CurvesKey private_key) throws IOException
	{
		if(key_ring.containsKey("self_public") || key_ring.containsKey("self_private"))
		{
			key_ring.remove("self_public");
			key_ring.remove("self_private");
		}
		key_ring.put("self_public", public_key);
		key_ring.put("self_private", private_key);
		save_key_ring();
	}

	//Almacena los cambios del llavero
	private void save_key_ring() throws IOException
	{
		storage.delete();
		storage.createNewFile();
		try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(storage)))
		{
			oos.writeObject(key_ring);
		} catch (IOException e) 
		{
			System.out.println(e.getMessage());
		}
	}
	//Exporta la llave pública del usuario a un archivo
	public void export_public_key(String owner, File export)
	{
		try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(export)))
		{
			CurvesKey key = key_ring.get(owner);
			oos.writeObject(key);
		} catch (IOException e) 
		{
			System.out.println(e.getMessage());
		}
	}
	
	//Agrega la llave contenida en un archivo al llavero
	public void import_public_key(String owner, File export)
	{
		try(ObjectInputStream ois = new ObjectInputStream(new FileInputStream(export)))
		{
			CurvesKey key = (CurvesKey) ois.readObject();
			add_public_key(owner, key);
		} catch (IOException | ClassNotFoundException e) 
		{
			System.out.println(e.getMessage());
		}
	}
	
}
