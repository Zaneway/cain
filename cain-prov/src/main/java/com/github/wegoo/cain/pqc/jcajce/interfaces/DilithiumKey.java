package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.DilithiumParameterSpec;

public interface DilithiumKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a DilithiumParameterSpec
     */
    DilithiumParameterSpec getParameterSpec();
}
