package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.FalconParameterSpec;

public interface FalconKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FalconParameterSpec
     */
    FalconParameterSpec getParameterSpec();
}
