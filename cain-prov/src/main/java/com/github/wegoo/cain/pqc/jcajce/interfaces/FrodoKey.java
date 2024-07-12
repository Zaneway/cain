package com.github.wegoo.cain.pqc.jcajce.interfaces;

import com.github.wegoo.cain.pqc.jcajce.spec.FrodoParameterSpec;

import java.security.Key;

public interface FrodoKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FrodoParameterSpec
     */
    FrodoParameterSpec getParameterSpec();
}
