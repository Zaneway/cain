package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.NTRUParameterSpec;

public interface NTRUKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a NTRUParameterSpec
     */
    NTRUParameterSpec getParameterSpec();
}
