void
AudioEngine::play()
{
    if ( QThread::currentThread() != thread() )
    {
        QMetaObject::invokeMethod( this, "play", Qt::QueuedConnection );
        return;
    }

    Q_D( AudioEngine );

    tDebug( LOGEXTRA ) << Q_FUNC_INFO;

    if ( isPaused() )
    {
        d->audioOutput->play();
        emit resumed();

        sendNowPlayingNotification( Tomahawk::InfoSystem::InfoNowResumed );
    }
    else
    {
        if ( !d->currentTrack && d->playlist && d->playlist->nextResult() )
        {
            loadNextTrack();
        }
        else
            next();
    }
}
