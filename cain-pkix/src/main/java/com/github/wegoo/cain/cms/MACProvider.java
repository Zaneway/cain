package com.github.wegoo.cain.cms;

import java.io.IOException;

interface MACProvider
{
    byte[] getMAC();

    void init() throws IOException;
}

