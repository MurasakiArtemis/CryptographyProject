package cryptography;

import java.io.Serializable;

public class CurvesKey implements Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
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
