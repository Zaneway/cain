package com.github.wegoo.cain.mime;

import java.io.IOException;

public interface MimeMultipartContext
    extends MimeContext
{
    public MimeContext createContext(int partNo)
        throws IOException;
}
