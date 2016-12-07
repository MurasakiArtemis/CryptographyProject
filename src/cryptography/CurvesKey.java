package cryptography;

public class CurvesKey 
{
	public Punto generator;
	public Punto q;
	public int m;
	
	public CurvesKey(Punto generator, Punto q)
	{
		this.generator = generator;
		this.q = q;
	}
	
	public CurvesKey(int m)
	{
		this.m = m;
	}
}
