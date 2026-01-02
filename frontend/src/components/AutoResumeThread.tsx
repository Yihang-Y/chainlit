import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useRecoilState } from 'recoil';
import { toast } from 'sonner';

import {
  resumeThreadErrorState,
  useChatInteract,
  useChatSession,
  useConfig
} from '@chainlit/react-client';

interface Props {
  id: string;
}

export default function AutoResumeThread({ id }: Props) {
  const navigate = useNavigate();
  const { config } = useConfig();
  const { clear, setIdToResume } = useChatInteract();
  const { session, idToResume } = useChatSession();
  const [resumeThreadError, setResumeThreadError] = useRecoilState(
    resumeThreadErrorState
  );

  // Handle thread resumption
  useEffect(() => {
    if (!config?.threadResumable) {
      return;
    }

    const connected = !!session?.socket?.connected;

    console.log('[AUTO_RESUME] Effect triggered:', {
      threadResumable: config?.threadResumable,
      id,
      idToResume,
      connected
    });

    // ✅ 关键：只要 idToResume 已经是目标 id，就不要再做任何事
    // 让 App 的 connect effect 去负责"连上/重连"
    if (idToResume === id) {
      console.log('[AUTO_RESUME] idToResume already set, skipping');
      return;
    }

    // ✅ 关键：只有"已连接的旧会话"才需要 clear（为了切线程）
    if (connected) {
      console.log('[AUTO_RESUME] Connected to another session, clearing before resume');
      clear(); // 会断开旧 socket
    } else {
      console.log('[AUTO_RESUME] Not connected, skip clear (avoid disconnect loop)');
    }

    console.log('[AUTO_RESUME] Setting idToResume:', id);
    setIdToResume(id);

    if (!config?.dataPersistence) {
      navigate('/');
    }
  }, [
    config?.threadResumable,
    config?.dataPersistence,
    id,
    idToResume,
    session?.socket?.connected, // ✅ 不要依赖整个 session 对象
    clear,
    setIdToResume,
    navigate
  ]);

  // Handle session errors when resuming
  useEffect(() => {
    console.log('[AUTO_RESUME] Error check:', {
      id,
      idToResume,
      hasError: !!session?.error,
      resumeThreadError,
      note: id !== idToResume ? 'Id mismatch (idToResume may not be updated yet due to async state update)' : 'Ids match'
    });

    // Note: idToResume may not be updated immediately after setIdToResume() call
    // because React/Recoil state updates are asynchronous. This effect will run again
    // when idToResume updates, so we can check errors then.
    if (id !== idToResume) {
      console.log('[AUTO_RESUME] Id mismatch, skipping error check (will retry when idToResume updates)');
      return;
    }
    
    // Only check errors when idToResume matches id (meaning the state has been updated)
    if (session?.error) {
      console.log('[AUTO_RESUME] Session error detected');
      toast.error("Couldn't resume chat");
      navigate('/');
    }
  }, [session, idToResume, id, navigate]);

  // Handle resume thread errors
  useEffect(() => {
    if (resumeThreadError) {
      console.log('[AUTO_RESUME] Resume thread error:', resumeThreadError);
      toast.error("Couldn't resume chat: " + resumeThreadError);
      navigate('/');
      setResumeThreadError(undefined);
    }
  }, [resumeThreadError, navigate, setResumeThreadError]);

  return null;
}
