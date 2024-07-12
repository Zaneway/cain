package com.github.wegoo.cain.pqc.crypto.falcon;

class ComplexNumberWrapper
{
    FalconFPR re;
    FalconFPR im;

    ComplexNumberWrapper(FalconFPR re, FalconFPR im)
    {
        this.re = re;
        this.im = im;
    }
}
