import { memo, useContext, useState } from 'react';
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
  const { loading, askUser, editable } = useContext(MessageContext);
  const { editMessage } = useChatInteract();
  const setMessages = useSetRecoilState(messagesState);

  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState(message.output || '');

  const disabled = loading;

  const handleSave = () => {
    if (!draft.trim()) return;

    // 1) 立即更新 UI（overwrite：截断后续）
    setMessages((prev) => {
      const index = prev.findIndex((m) => m.id === message.id);
      if (index === -1) return prev;

      const slice = prev.slice(0, index + 1);

      slice[index] = {
        ...slice[index],
        output: draft,
        steps: [] // 可选但建议：清掉可能挂载的 steps，和 UserMessage 思路一致
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
        <MessageContent
        ref={contentRef}
        elements={elements}
        message={message}
        allowHtml={allowHtml}
        latex={latex}
        />


          {editable && (
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-1 right-1 invisible group-hover:visible"
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
