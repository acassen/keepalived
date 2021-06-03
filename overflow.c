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
	      bool retry = false;
        if ( newState == AudioOutput::Error )
        {
            retry = ( audioRetryCounter < 2 );
            audioRetryCounter++;

            if ( !retry )
            {
                q_ptr->stop( AudioEngine::UnknownError );
            }
        }

        if ( newState == AudioOutput::Stopped || retry )
        {
            tDebug() << Q_FUNC_INFO << "Finding next track." << oldState << newState;
            if ( q_ptr->canGoNext() )
            {
                q_ptr->loadNextTrack();
            }
            else
            {
                if ( !playlist.isNull() && playlist.data()->retryMode() == Tomahawk::PlaylistModes::Retry )
                    waitingOnNewTrack = true;

                q_ptr->stop();
            }
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
AudioEngine*
AudioEngine::instance()
{
    return AudioEnginePrivate::s_instance;
}


AudioEngine::AudioEngine()
    : QObject()
    , d_ptr( new AudioEnginePrivate( this ) )
{
    Q_D( AudioEngine );
	    
	    
	    AudioEngine::~AudioEngine()
{
    tDebug() << Q_FUNC_INFO;

    TomahawkSettings::instance()->setVolume( volume() );
    TomahawkSettings::instance()->setMuted( isMuted() );

    delete d_ptr;
}

