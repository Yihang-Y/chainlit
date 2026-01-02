import { useState, useEffect } from 'react';
import { useChatInteract, useChatSession, useChatMessages } from '@chainlit/react-client';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import { GitBranch } from 'lucide-react';
import { toast } from 'sonner';

export default function BranchSwitcher() {
  const { switchBranch } = useChatInteract();
  const { session } = useChatSession();
  const { threadId } = useChatMessages();
  const [currentBranch, setCurrentBranch] = useState<string>('main');
  const [branches, setBranches] = useState<Array<{ branch_id: string; forked_at: string; forked_from: string }>>([]);
  const [loading, setLoading] = useState(false);

  // Fetch branch info from thread metadata
  useEffect(() => {
    const fetchBranchInfo = async () => {
      if (!threadId || !session?.socket) {
        // Reset to default if no thread
        setCurrentBranch('main');
        setBranches([]);
        return;
      }

      try {
        // Get thread metadata to fetch branch info
        const response: any = await session.socket.emitWithAck('get_thread_metadata', {
          thread_id: threadId
        });

        if (response?.success) {
          const metadata = response.metadata || {};
          setCurrentBranch(metadata.current_branch_id || 'main');
          setBranches(metadata.branches || []);
        } else {
          // If request failed, use defaults
          setCurrentBranch('main');
          setBranches([]);
        }
      } catch (error) {
        console.error('Failed to fetch branch info:', error);
        // On error, use defaults
        setCurrentBranch('main');
        setBranches([]);
      }
    };

    fetchBranchInfo();

    // Listen for branch_switched event to update UI
    if (session?.socket) {
      const handleBranchSwitched = (data: { branch_id: string; thread_id: string }) => {
        if (data.thread_id === threadId) {
          // Refresh branch info when branch is switched
          fetchBranchInfo();
        }
      };

      session.socket.on('branch_switched', handleBranchSwitched);

      return () => {
        session.socket?.off('branch_switched', handleBranchSwitched);
      };
    }
  }, [threadId, session?.socket]);

  const handleSwitchBranch = async (branchId: string) => {
    if (branchId === currentBranch) return;

    setLoading(true);
    try {
      const response = await switchBranch(branchId);
      if (response.success) {
        // Update local state optimistically
        setCurrentBranch(branchId);
        toast.success('分支已切换', {
          description: `已切换到分支: ${branchId === 'main' ? '主分支' : branchId.slice(0, 8)}`,
        });
        // The branch_switched event will trigger UI update via useEffect
        // No need to manually fetch here
      } else {
        toast.error('切换失败', {
          description: response.error || '未知错误',
        });
      }
    } catch (error) {
      toast.error('切换失败', {
        description: '网络错误',
      });
    } finally {
      setLoading(false);
    }
  };

  // Always show the branch switcher
  // Show current branch indicator and allow switching when branches exist
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="text-muted-foreground hover:text-muted-foreground relative"
          disabled={loading}
          title={`当前分支: ${currentBranch === 'main' ? '主分支' : currentBranch.slice(0, 8)}`}
        >
          <GitBranch className="h-4 w-4" />
          {currentBranch !== 'main' && (
            <span className="absolute -top-1 -right-1 h-2 w-2 bg-blue-500 rounded-full" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>切换分支</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => handleSwitchBranch('main')}
          className={currentBranch === 'main' ? 'bg-accent' : ''}
        >
          <div className="flex flex-col w-full">
            <div className="flex items-center justify-between">
              <span className="font-medium">主分支</span>
              {currentBranch === 'main' && (
                <span className="text-xs text-muted-foreground">✓ 当前</span>
              )}
            </div>
          </div>
        </DropdownMenuItem>
        {branches.length > 0 && <DropdownMenuSeparator />}
        {branches.map((branch) => (
          <DropdownMenuItem
            key={branch.branch_id}
            onClick={() => handleSwitchBranch(branch.branch_id)}
            className={currentBranch === branch.branch_id ? 'bg-accent' : ''}
          >
            <div className="flex flex-col w-full">
              <div className="flex items-center justify-between">
                <span className="font-medium">
                  {branch.branch_id.slice(0, 8)}...
                </span>
                {currentBranch === branch.branch_id && (
                  <span className="text-xs text-muted-foreground">✓ 当前</span>
                )}
              </div>
              <span className="text-xs text-muted-foreground">
                {new Date(branch.forked_at).toLocaleString('zh-CN')}
              </span>
            </div>
          </DropdownMenuItem>
        ))}
        {branches.length === 0 && (
          <div className="px-2 py-1.5 text-sm text-muted-foreground">
            暂无其他分支
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

