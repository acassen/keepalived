 const char* start_of_filename = p;
            while ((*p != '\0') && (*p != ';')) {
                if (*p == '%') {
                    if ((*(p+1) == '\0') || (!isxdigit(*(p+1))) || (!isxdigit(*p+2))) {
                        return -18;
                    }
                    p += 3;
   {  
    "enabled":1,
    "version_min":300000,
    "title":"multipart Content-Disposition should allow filename* field (1/6)",
    "client":{  
      "ip":"200.249.12.31",
      "port":123
	@@ -50,7 +50,7 @@
  {  
    "enabled":1,
    "version_min":300000,
    "title":"multipart Content-Disposition should allow filename* field (2/6)",
    "client":{  
      "ip":"200.249.12.31",
      "port":123
if ( newState == AudioOutput::Loading )
    {
        // We don't emit this state to listeners - yet.
        state = AudioEngine::Loading;
    }
    else if ( newState == AudioOutput::Buffering )
    {
        if ( underrunCount > UNDERRUNTHRESHOLD && !underrunNotified )
        {
            underrunNotified = true;
            //FIXME: Actually notify
        }
        else
            underrunCount++;
    }
