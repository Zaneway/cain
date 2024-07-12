package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.CMCEParameterSpec;

public interface CMCEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a CMCEParameterSpec
     */
    CMCEParameterSpec getParameterSpec();
}
