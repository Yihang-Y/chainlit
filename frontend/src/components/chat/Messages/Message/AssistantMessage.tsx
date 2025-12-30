import { memo, useContext, useState, useMemo } from 'react';
import { useSetRecoilState } from 'recoil';

import {
  IStep,
  IMessageElement,
  messagesState,
  useChatInteract
} from '@chainlit/react-client';

import { MessageContext } from 'contexts/MessageContext';
import AutoResizeTextarea from '@/components/AutoResizeTextarea';
import { Pencil } from '@/components/icons/Pencil';
import { Button } from '@/components/ui/button';

import { MessageContent } from './Content';

interface Props {
  message: IStep;
  elements: IMessageElement[];
  contentRef?: React.RefObject<HTMLDivElement>;
  allowHtml?: boolean;
  latex?: boolean;
}

const AssistantMessage = memo(function AssistantMessage({
  message,
  elements,
  contentRef,
  allowHtml,
  latex
}: Props) {
  const { loading, editable } = useContext(MessageContext);
  const { editMessage } = useChatInteract();
  const setMessages = useSetRecoilState(messagesState);

  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState(message.output || '');

  const disabled = loading;

  // 兼容 parentId 字段命名差异
  const parentId = (message as any).parentId ?? (message as any).parent_id ?? (message as any).parentId;

  const handleSave = () => {
    if (!draft.trim()) return;

    // 1) 立即更新 UI + 清理下游
    setMessages((prev) => {
      const index = prev.findIndex((m) => m.id === message.id);
      if (index === -1) return prev;

      // 默认：截断到当前 message
      let cutIndex = index;

      // 新策略：截断到 parent 的“后一个”
      if (parentId) {
        const parentIndex = prev.findIndex((m) => m.id === parentId);
        if (parentIndex !== -1) {
          cutIndex = Math.min(parentIndex + 1, prev.length - 1);
        }
      }

      // ⚠️ 关键：不能把自己截断掉，否则 patch 看不到
      cutIndex = Math.max(cutIndex, index);

      const slice = prev.slice(0, cutIndex + 1);

      // 更新当前 message（在 slice 里一定存在，因为上面保证了 cutIndex >= index）
      slice[index] = {
        ...slice[index],
        output: draft,
        steps: [] // 建议清掉 children，避免父输出变了 children 仍旧
      };

      return slice;
    });

    // 2) 通知后端持久化
    editMessage({
      ...message,
      output: draft
    });

    setIsEditing(false);
  };

  return (
    <div className="flex flex-col items-start gap-2 w-full">
      {!isEditing && (
        <div className="relative group w-full">
          <div className="pr-8">
            <MessageContent
              ref={contentRef}
              elements={elements}
              message={message}
              allowHtml={allowHtml}
              latex={latex}
            />
          </div>

          {editable && (
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-1 right-1 invisible group-hover:visible z-10"
              onClick={() => {
                setDraft(message.output || '');
                setIsEditing(true);
              }}
              disabled={disabled}
            >
              <Pencil />
            </Button>
          )}
        </div>
      )}

      {isEditing && (
        <div className="w-full bg-accent rounded-xl p-3 flex flex-col gap-2">
          <AutoResizeTextarea
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            maxHeight={300}
            className="bg-transparent text-base"
          />

          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => {
                setDraft(message.output || '');
                setIsEditing(false);
              }}
            >
              取消
            </Button>
            <Button onClick={handleSave} disabled={disabled}>
              保存
            </Button>
          </div>
        </div>
      )}
    </div>
  );
});

export default AssistantMessage;
