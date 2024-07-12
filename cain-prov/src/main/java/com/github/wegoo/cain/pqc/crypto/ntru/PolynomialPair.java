package com.github.wegoo.cain.pqc.crypto.ntru;

import com.github.wegoo.cain.pqc.math.ntru.Polynomial;

/**
 * Class containing a pair of polynomials.
 * <p>
 * Note that this class is merely a container of two polynomials and does not guarantee the properties for each of them.
 */
class PolynomialPair
{
    private final Polynomial a;
    private final Polynomial b;

    public PolynomialPair(Polynomial a, Polynomial b)
    {
        this.a = a;
        this.b = b;
    }

    public Polynomial f()
    {
        return this.a;
    }

    public Polynomial g()
    {
        return this.b;
    }

    public Polynomial r()
    {
        return this.a;
    }

    public Polynomial m()
    {
        return this.b;
    }
}
