package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.HQCParameterSpec;

public interface HQCKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a HQCParameterSpec
     */
    HQCParameterSpec getParameterSpec();
}
