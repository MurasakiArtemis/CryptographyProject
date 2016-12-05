package cryptography;

public class PuntoCC {
	
	private Punto x;
	private long y;

	public PuntoCC() {
		
	}
	
	public PuntoCC(Punto x,long y) {
		this.x=x;
		this.y=y;
	}

	public Punto getX() {
		return x;
	}

	public void setX(Punto x) {
		this.x = x;
	}

	public long getY() {
		return y;
	}

	public void setY(long y) {
		this.y = y;
	}

}
