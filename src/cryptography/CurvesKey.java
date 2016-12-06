package cryptography;

public class CurvesKey 
{
	public Punto generator;
	public Punto q;
	
	public CurvesKey(Punto generator, Punto q)
	{
		this.generator = generator;
		this.q = q;
	}
}
