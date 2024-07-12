package com.github.wegoo.cain.asn1.x9;

import com.github.wegoo.cain.math.ec.ECCurve;

/**
 * A holding class that allows for X9ECParameters to be lazily constructed.
 */
public abstract class X9ECParametersHolder
{
    private ECCurve curve;
    private X9ECParameters params;

    public synchronized ECCurve getCurve()
    {
        if (curve == null)
        {
            curve = createCurve();
        }

        return curve;
    }

    public synchronized X9ECParameters getParameters()
    {
        if (params == null)
        {
            params = createParameters();
        }

        return params;
    }

    protected ECCurve createCurve()
    {
        return createParameters().getCurve();
    }

    protected abstract X9ECParameters createParameters();
}
