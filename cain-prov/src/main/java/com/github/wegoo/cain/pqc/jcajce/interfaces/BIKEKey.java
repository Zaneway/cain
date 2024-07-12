package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.BIKEParameterSpec;

public interface BIKEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a BIKEParameterSpec
     */
    BIKEParameterSpec getParameterSpec();
}
