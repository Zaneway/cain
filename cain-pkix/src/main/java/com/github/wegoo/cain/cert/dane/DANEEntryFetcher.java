package com.github.wegoo.cain.cert.dane;

import java.util.List;

public interface DANEEntryFetcher
{
    List getEntries() throws DANEException;
}
