package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.RainbowParameterSpec;

public interface RainbowKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a RainbowParameterSpec
     */
    RainbowParameterSpec getParameterSpec();
}
