package com.github.wegoo.cain.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import com.github.wegoo.cain.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
