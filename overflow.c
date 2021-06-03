void
AudioEngine::pause()
{
    if ( QThread::currentThread() != thread() )
    {
        QMetaObject::invokeMethod( this, "pause", Qt::QueuedConnection );
        return;
    }

    Q_D( AudioEngine );

    tDebug( LOGEXTRA ) << Q_FUNC_INFO;

    d->audioOutput->pause();
    emit paused();

    Tomahawk::InfoSystem::InfoSystem::instance()->pushInfo( Tomahawk::InfoSystem::InfoPushData( s_aeInfoIdentifier, Tomahawk::InfoSystem::InfoNowPaused, QVariant(), Tomahawk::InfoSystem::PushNoFlag ) );
}
