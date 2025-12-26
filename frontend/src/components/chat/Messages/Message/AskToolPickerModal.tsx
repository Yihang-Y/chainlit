import { MessageContext } from 'contexts/MessageContext';
import { useContext, useMemo, useState, useEffect } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter
} from '@/components/ui/dialog';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger
} from '@/components/ui/tooltip';

type ToolItem = {
  id: string;
  name: string;
  description?: string | null;
  mcp?: string[] | null;
  mcp_url?: string | null;
};

type ToolPickerSpec = {
  type: 'tool_picker';
  step_id: string;
  title?: string;
  prompt?: string;
  keys?: string[];
  tools: ToolItem[];
};

const ToolRow = ({
  tool,
  selected,
  onToggle
}: {
  tool: ToolItem;
  selected: boolean;
  onToggle: () => void;
}) => {
  const title = tool.name || tool.id;

  const row = (
    <button
      type="button"
      onClick={onToggle}
      className={[
        'w-full text-left rounded-md border px-3 py-2 transition',
        selected ? 'border-primary' : 'border-border',
        'hover:bg-muted'
      ].join(' ')}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {/* 简单选中标识（不依赖额外组件） */}
            <span
              className={[
                'inline-flex h-4 w-4 items-center justify-center rounded border text-xs',
                selected ? 'border-primary' : 'border-border'
              ].join(' ')}
              aria-hidden="true"
            >
              {selected ? '✓' : ''}
            </span>

            <div className="font-medium truncate">{title}</div>
          </div>

          {tool.description ? (
            <div className="mt-1 text-sm text-muted-foreground line-clamp-2">
              {tool.description}
            </div>
          ) : null}

          {tool.mcp?.length ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {tool.mcp.slice(0, 8).map((t) => (
                <span
                  key={t}
                  className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground"
                >
                  {t}
                </span>
              ))}
            </div>
          ) : null}
        </div>

        {tool.mcp_url ? (
          <Button
            variant="outline"
            size="sm"
            className="shrink-0"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation(); // 避免点击链接导致 toggle
              window.open(tool.mcp_url!, '_blank', 'noopener,noreferrer');
            }}
          >
            Open
          </Button>
        ) : null}
      </div>
    </button>
  );

  if (tool.description && tool.description.length > 140) {
    return (
      <TooltipProvider delayDuration={100}>
        <Tooltip>
          <TooltipTrigger asChild>{row}</TooltipTrigger>
          <TooltipContent>
            <p className="max-w-xs whitespace-pre-wrap">{tool.description}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return row;
};

const AskToolPickerModal = ({ messageId }: { messageId: string }) => {
  const { loading, askUser } = useContext(MessageContext);

  const belongsToMessage = askUser?.spec.step_id === messageId;
  const isToolPicker = askUser?.spec.type === 'tool_picker';
  if (!belongsToMessage || !isToolPicker) return null;

  const spec = askUser.spec as unknown as ToolPickerSpec;

  const [open, setOpen] = useState(true);
  const [query, setQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    setOpen(true);
    setQuery('');
    setSelectedIds(new Set());
  }, [spec.step_id]);

  const allowedTools = useMemo(() => {
    const tools = Array.isArray(spec.tools) ? spec.tools : [];
    if (!spec.keys?.length) return tools;
    const allow = new Set(spec.keys);
    return tools.filter((t) => allow.has(t.id));
  }, [spec.tools, spec.keys]);

  const filteredTools = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allowedTools;

    return allowedTools.filter((t) => {
      const hay = [t.id, t.name, t.description, ...(t.mcp || []), t.mcp_url]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [allowedTools, query]);

  const title = spec.title || 'Choose tools';
  const prompt =
    spec.prompt || 'Select one or more tools you want the assistant to use next.';

  const selectedCount = selectedIds.size;
  const confirmDisabled = loading || selectedCount === 0;

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const clearSelection = () => setSelectedIds(new Set());

  const onConfirm = () => {
    if (selectedIds.size === 0) return;

    const ids = Array.from(selectedIds);

    // 可选：也把 tool_name/mcp_url 列表回传（后端更好用）
    const chosenTools = allowedTools.filter((t) => selectedIds.has(t.id));

    askUser?.callback({
      type: 'tool_picker',
      tool_ids: ids,
      tools: chosenTools.map((t) => ({
        id: t.id,
        name: t.name,
        mcp_url: t.mcp_url ?? undefined
      })),
      query: query.trim() || undefined
    });

    setOpen(false);
  };

  const onCancel = () => {
    askUser?.callback({
      type: 'tool_picker',
      tool_ids: [],
      cancelled: true
    });
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={(v) => setOpen(v)}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{prompt}</DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Input
              placeholder="Search tools..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              disabled={loading}
            />
            <div className="text-xs text-muted-foreground whitespace-nowrap">
              Selected: {selectedCount}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={clearSelection}
              disabled={loading || selectedCount === 0}
            >
              Clear
            </Button>
          </div>

          <div className="max-h-80 overflow-auto space-y-2 pr-1">
            {filteredTools.length ? (
              filteredTools.map((t) => (
                <ToolRow
                  key={t.id}
                  tool={t}
                  selected={selectedIds.has(t.id)}
                  onToggle={() => toggleSelect(t.id)}
                />
              ))
            ) : (
              <div className="text-sm text-muted-foreground">
                No tools match your search.
              </div>
            )}
          </div>
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={confirmDisabled}>
            Confirm
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export { AskToolPickerModal };
