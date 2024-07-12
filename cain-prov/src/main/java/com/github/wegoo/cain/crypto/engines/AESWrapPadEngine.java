package com.github.wegoo.cain.crypto.engines;

public class AESWrapPadEngine
    extends RFC5649WrapEngine
{
    public AESWrapPadEngine()
    {
        super(AESEngine.newInstance());
    }
}
