import { useEffect } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { useSetRecoilState } from 'recoil';

import Page from 'pages/Page';

import {
  threadHistoryState,
  useChatMessages,
  useConfig
} from '@chainlit/react-client';

import AutoResumeThread from '@/components/AutoResumeThread';
import { Loader } from '@/components/Loader';
import { ReadOnlyThread } from '@/components/ReadOnlyThread';
import Chat from '@/components/chat';

export default function ThreadPage() {
  const { id } = useParams();
  const location = useLocation();
  const { config } = useConfig();

  const setThreadHistory = useSetRecoilState(threadHistoryState);

  const { threadId } = useChatMessages();

  const isCurrentThread = threadId === id;

  // Debug: Log thread state
  console.log('[THREAD] State:', {
    urlId: id,
    threadId,
    isCurrentThread,
    threadResumable: config?.threadResumable,
    isSharedRoute: location.pathname.startsWith('/share/')
  });

  useEffect(() => {
    setThreadHistory((prev) => {
      if (prev?.currentThreadId === id) return prev;
      return { ...prev, currentThreadId: id };
    });
  }, [id, setThreadHistory]);

  const isSharedRoute = location.pathname.startsWith('/share/');

  // Determine what to render
  let renderContent: JSX.Element;
  let renderReason = '';

  if (isSharedRoute) {
    renderContent = <ReadOnlyThread id={id!} />;
    renderReason = 'Shared route';
  } else if (config?.threadResumable) {
    // Show loader only if we're waiting for threadId to be set
    // This prevents infinite loading when threadId is undefined
    if (!threadId && !isCurrentThread) {
      renderContent = (
        <>
          <AutoResumeThread id={id!} />
          <div className="flex flex-grow items-center justify-center">
            <Loader className="!size-6" />
          </div>
        </>
      );
      renderReason = 'Thread resumable, waiting for threadId, showing loader';
    } else if (!isCurrentThread) {
      renderContent = <AutoResumeThread id={id!} />;
      renderReason = 'Thread resumable, not current thread, showing AutoResumeThread';
    } else {
      renderContent = <Chat />;
      renderReason = 'Thread resumable, current thread, showing Chat';
    }
  } else if (config && !config.threadResumable) {
    if (isCurrentThread) {
      renderContent = <Chat />;
      renderReason = 'Not resumable, current thread, showing Chat';
    } else {
      renderContent = <ReadOnlyThread id={id!} />;
      renderReason = 'Not resumable, not current thread, showing ReadOnlyThread';
    }
  } else {
    // Fallback: show loader if config is not loaded yet
    renderContent = (
      <div className="flex flex-grow items-center justify-center">
        <Loader className="!size-6" />
      </div>
    );
    renderReason = 'No config or conditions not met, showing loader';
  }

  console.log('[THREAD] Render decision:', renderReason);

  return (
    <Page>
      {renderContent}
    </Page>
  );
}
