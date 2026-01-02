import { cn } from '@/lib/utils';
import { useEffect, useRef } from 'react';
import { RouterProvider } from 'react-router-dom';
import { useRecoilValue } from 'recoil';
import { router } from 'router';

import { useAuth, useChatSession, useConfig } from '@chainlit/react-client';

import ChatSettingsModal from './components/ChatSettings';
import { ThemeProvider } from './components/ThemeProvider';
import { Loader } from '@/components/Loader';
import { Toaster } from '@/components/ui/sonner';

import { userEnvState } from 'state/user';

declare global {
  interface Window {
    cl_shadowRootElement?: HTMLDivElement;
    transports?: string[];
    theme?: {
      light: Record<string, string>;
      dark: Record<string, string>;
    };
  }
}

function App() {
  const { config, error: configError } = useConfig();

  const { isAuthenticated, data, isReady } = useAuth();
  const userEnv = useRecoilValue(userEnvState);
  const { connect, chatProfile, setChatProfile, session, idToResume } = useChatSession();
  const connectionAttemptRef = useRef<string | null>(null);
  const isConnectingRef = useRef<boolean>(false);
  const prevConnRef = useRef<{ socket: any; connected: boolean }>({
    socket: null,
    connected: false
  });
  const connectingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // ✅ 在外部计算 hasError，避免在依赖数组中放 session?.error 对象
  const hasError = !!session?.error;

  const configLoaded = !!config;

  const chatProfileOk = configLoaded
    ? config.chatProfiles.length
      ? !!chatProfile
      : true
    : false;

  // Debug: Log current state
  console.log('[APP] State:', {
    isAuthenticated,
    isReady,
    configLoaded,
    chatProfileOk,
    chatProfile,
    hasSocket: !!session?.socket,
    socketConnected: !!session?.socket?.connected,
    socketError: !!session?.error,
    configError: !!configError
  });

  // Set default chatProfile when config loads
  useEffect(() => {
    console.log('[APP] chatProfile useEffect:', {
      configLoaded,
      hasConfig: !!config,
      chatProfilesLength: config?.chatProfiles?.length,
      currentChatProfile: chatProfile
    });

    if (
      !configLoaded ||
      !config ||
      !config.chatProfiles?.length ||
      chatProfile
    ) {
      console.log('[APP] chatProfile useEffect: Skipping (conditions not met)');
      return;
    }

    const defaultChatProfile = config.chatProfiles.find(
      (profile) => profile.default
    );

    if (defaultChatProfile) {
      console.log('[APP] chatProfile useEffect: Setting default profile:', defaultChatProfile.name);
      setChatProfile(defaultChatProfile.name);
    } else {
      console.log('[APP] chatProfile useEffect: Setting first profile:', config.chatProfiles[0].name);
      setChatProfile(config.chatProfiles[0].name);
    }
  }, [configLoaded, config, chatProfile, setChatProfile]);

  // Handle socket connection
  useEffect(() => {
    const socket = session?.socket;
    const isConnected = !!socket?.connected;

    // ✅ 更严谨的 edge 计算逻辑（避免 socket 为空时算 edge）
    let socketInstanceChanged = false;
    let disconnectedEdge = false;

    // 没有 socket：重置基线，不算 edge
    if (!socket) {
      if (prevConnRef.current.socket !== null) {
        socketInstanceChanged = true;
      }
      prevConnRef.current.socket = null;
      prevConnRef.current.connected = false;
    } else if (prevConnRef.current.socket !== socket) {
      // socket 实例变化：不算 edge，重置基线
      socketInstanceChanged = true;
      console.log('[APP] Socket instance changed, resetting prev connection state');
      prevConnRef.current.socket = socket;
      prevConnRef.current.connected = isConnected;
    } else {
      // 同一个 socket 才算 edge
      disconnectedEdge = prevConnRef.current.connected && !isConnected;
      prevConnRef.current.connected = isConnected;
    }

    console.log('[APP] Connection useEffect triggered:', {
      isAuthenticated,
      isReady,
      chatProfileOk,
      hasSocket: !!socket,
      socketConnected: isConnected,
      socketError: hasError,
      idToResume,
      disconnectedEdge,
      socketInstanceChanged
    });

    if (!isAuthenticated || !isReady || !chatProfileOk) {
      console.log('[APP] Connection useEffect: Skipping (conditions not met)');
      return;
    }

    // userEnv 关键字段摘要（按你实际情况挑）
    const envKey = JSON.stringify(userEnv ?? {});

    // Include idToResume in connectionKey so that when idToResume changes,
    // we can reconnect with the new thread id
    const connectionKey =
      `${isAuthenticated}-${isReady}-${chatProfileOk}-${chatProfile || 'none'}-${envKey}-${idToResume || 'none'}-${hasError ? 'err' : 'ok'}`;

    console.log('[APP] Connection check:', {
      isConnected,
      hasError,
      idToResume,
      connectionKey,
      previousKey: connectionAttemptRef.current,
      disconnectedEdge
    });

    // 已连接且无错：记下 key 并退出
    if (isConnected && !hasError) {
      // Clear connecting timeout if exists
      if (connectingTimeoutRef.current) {
        clearTimeout(connectingTimeoutRef.current);
        connectingTimeoutRef.current = null;
      }
      // Reset connecting flag when connected
      isConnectingRef.current = false;
      // Only update connectionAttemptRef if key changed (e.g., idToResume changed)
      // This prevents unnecessary updates when socket.connected changes
      if (connectionAttemptRef.current !== connectionKey) {
        console.log('[APP] Connection: Already connected, updating connection key');
        connectionAttemptRef.current = connectionKey;
      }
      return;
    }

    // 如果正在连接中，跳过（避免重复连接）
    if (isConnectingRef.current) {
      console.log('[APP] Connection: Already connecting, skipping');
      return;
    }

    // ✅ 只有真的"从连着变断开"或"有 error"才允许清 attemptRef
    // 这避免把"连接尚未完成"误判成"断开了"
    if (disconnectedEdge || hasError) {
      console.log('[APP] Connection: Socket disconnected (edge detected) or error, clearing attempt ref');
      connectionAttemptRef.current = null;
      isConnectingRef.current = false; // Reset connecting flag
      // Clear timeout if exists
      if (connectingTimeoutRef.current) {
        clearTimeout(connectingTimeoutRef.current);
        connectingTimeoutRef.current = null;
      }
    }

    // 如果已经尝试过连接且 key 相同，跳过（避免重复连接）
    if (connectionAttemptRef.current === connectionKey) {
      console.log('[APP] Connection: Already attempted with same key, skipping');
      return;
    }

    console.log('[APP] Connection: Attempting connection with key:', connectionKey);
    connectionAttemptRef.current = connectionKey;
    isConnectingRef.current = true; // Mark as connecting

    // ✅ 兜底：如果 connect 卡住不返回（既不 connected 也不 error），8s 后允许重试
    connectingTimeoutRef.current = setTimeout(() => {
      console.log('[APP] Connection: Timeout after 8s, clearing connecting flag to allow retry');
      isConnectingRef.current = false;
      connectionAttemptRef.current = null;
      connectingTimeoutRef.current = null;
    }, 8000);

    connect({ transports: window.transports, userEnv });
  }, [
    isAuthenticated,
    isReady,
    chatProfileOk,
    chatProfile,
    session?.socket,             // ✅ 加这个，让 effect 在 socket 实例切换时也触发
    session?.socket?.connected,
    hasError,
    connect,
    userEnv,
    idToResume
  ]);

  // Show error state if config fails to load
  if (configError && isAuthenticated) {
    console.log('[APP] Render: Config error state', { configError: configError.message });
    return (
      <ThemeProvider storageKey="vite-ui-theme" defaultTheme={data?.default_theme}>
        <div className="flex items-center justify-center fixed size-full p-2 top-0">
          <div className="text-center">
            <p className="text-lg font-semibold mb-2">Failed to load configuration</p>
            <p className="text-sm text-muted-foreground">{configError.message || 'Unknown error'}</p>
            <button
              onClick={() => window.location.reload()}
              className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md"
            >
              Reload
            </button>
          </div>
        </div>
      </ThemeProvider>
    );
  }

  // Show loading only if config is still loading (not if it failed)
  if (!configLoaded && isAuthenticated) {
    console.log('[APP] Render: Config loading state');
    return (
      <ThemeProvider storageKey="vite-ui-theme" defaultTheme={data?.default_theme}>
        <div className="flex items-center justify-center fixed size-full p-2 top-0">
          <Loader className="!size-6" />
        </div>
      </ThemeProvider>
    );
  }

  console.log('[APP] Render: Main app (isReady loading gate:', !isReady && isAuthenticated, ')');

  return (
    <ThemeProvider
      storageKey="vite-ui-theme"
      defaultTheme={data?.default_theme}
    >
      <Toaster richColors className="toast" position="top-right" />

      <ChatSettingsModal />
      <RouterProvider router={router} />

      {/* Only show loading gate if not ready AND authenticated (to avoid blocking login page) */}
      {!isReady && isAuthenticated && (
        <div
          className={cn(
            'bg-[hsl(var(--background))] flex items-center justify-center fixed size-full p-2 top-0 z-50'
          )}
        >
          <Loader className="!size-6" />
        </div>
      )}
    </ThemeProvider>
  );
}

export default App;
