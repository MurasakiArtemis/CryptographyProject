package cryptography;

import java.io.Serializable;

public class Punto implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private long x;
	private long y;
	
	public Punto() {
		// TODO Auto-generated constructor stub
	}
	
	public Punto(long x,long y){
		this.x=x;
		this.y=y;
	}

	public long getX() {
		return x;
	}

	public void setX(long x) {
		this.x = x;
	}

	public long getY() {
		return y;
	}

	public void setY(long y) {
		this.y = y;
	}

}
