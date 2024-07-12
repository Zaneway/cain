package com.github.wegoo.cain.openssl;

public class EncryptionException
    extends PEMException
{
    private Throwable cause;

    public EncryptionException(String msg)
    {
        super(msg);
    }

    public EncryptionException(String msg, Throwable ex)
    {
        super(msg);
        this.cause = ex;
    }

    public Throwable getCause()
    {
        return cause;
    }
}