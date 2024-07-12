package com.github.wegoo.cain.crypto.params;

import com.github.wegoo.cain.util.Arrays;

public class DSTU4145Parameters
    extends ECDomainParameters
{
    private final byte[] dke;

    public DSTU4145Parameters(ECDomainParameters ecParameters, byte[] dke)
    {
        super(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed());

        this.dke = Arrays.clone(dke);
    }

    public byte[] getDKE()
    {
        return Arrays.clone(dke);
    }
}
