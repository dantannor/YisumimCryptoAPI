package Logic;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

public class CryptoConfiguration 
{

	private byte[] m_digitalSignature;
	private byte[] m_DigtalSignaturePublicKey;
	private byte[] m_AesKey;
	private byte[] m_IV;
	
    public byte[] getIV()
    {
        return m_IV;
    }

    public void setIV(byte[] m_IV)
    {
        this.m_IV = m_IV;
    }

    public byte[] getAesKey()
	{
		return m_AesKey;
	}

	public void setAesKey(byte[] aesKey) 
	{
		this.m_AesKey = aesKey;
	}

    public byte[] getDigtalSignaturePublicKey()
    {
        return m_DigtalSignaturePublicKey;
    }

	public void setDigtalSignaturePublicKey(byte[] publicKey) {
		this.m_DigtalSignaturePublicKey = publicKey;
	}

	public byte[] getDigitalSignature() {
		return m_digitalSignature;
	}

	public void setDigitalSignature(byte[] digitalSignature) {
		this.m_digitalSignature = digitalSignature;
	}
}
