import React, { memo, useContext, useMemo, useRef, useState } from 'react';
import { useSetRecoilState } from 'recoil';

import {
  type IAction,
  type IMessageElement,
  type IStep,
  messagesState,
  useChatInteract
} from '@chainlit/react-client';

import { MessageContext } from 'contexts/MessageContext';
import AutoResizeTextarea from '@/components/AutoResizeTextarea';
import { Pencil } from '@/components/icons/Pencil';
import { Button } from '@/components/ui/button';

import Step from './Step';
import { MessageContent } from './Content';
import { Messages } from '..';
import { MessageButtons } from './Buttons';

interface Props {
  step: IStep;
  elements: IMessageElement[];
  actions: IAction[];
  indent: number;
  isRunning?: boolean;
}

const StepMessage = memo(function StepMessage({
  step,
  elements,
  actions,
  indent,
  isRunning
}: Props) {
  const { allowHtml, latex, loading, askUser, editable, onError } =
    useContext(MessageContext) as any; // 如果你们 MessageContext 没 onError，就把这行的 as any 去掉并移除 onError 使用

  const { editMessage } = useChatInteract();
  const setMessages = useSetRecoilState(messagesState);
  console.log('StepMessage render', step.id);

  const contentRef = useRef<HTMLDivElement>(null);

  // output 编辑态
  const [isEditingOutput, setIsEditingOutput] = useState(false);
  const [draftOutput, setDraftOutput] = useState(step.output || '');

  // input 编辑态（input 可能是对象/数组/字符串）
  const [isEditingInput, setIsEditingInput] = useState(false);
  const [draftInput, setDraftInput] = useState(() => {
    if (step.input == null) return '';
    return typeof step.input === 'string'
      ? step.input
      : JSON.stringify(step.input, null, 2);
  });

  const disabled = loading;

  const showInputSection = Boolean(step.input && step.showInput);
  const shouldRenderOutput = !showInputSection || Boolean(step.output);

  const childSteps = useMemo(
    () => step.steps?.filter((s) => !s.type.includes('message')) ?? [],
    [step.steps]
  );

  const commitStepPatch = (patch: Partial<IStep>) => {
    setMessages((prev) => {
      const index = prev.findIndex((m) => m.id === step.id);
      if (index === -1) return prev;
  
      const parentId = (step as any).parentId ?? (step as any).parent_id ?? step.parentId;
  
      // 默认还是截断到当前 step
      let cutIndex = index;
  
      // 如果能找到 parent，则改为截断到 parent 的“后一个”
      if (parentId) {
        const parentIndex = prev.findIndex((m) => m.id === parentId);
        if (parentIndex !== -1) {
          cutIndex = Math.min(parentIndex + 1, prev.length - 1);
        }
      }
  
      const slice = prev.slice(0, cutIndex + 1);
  
      // 更新当前 step 本身（如果当前 step 已经被截断掉了，就不会更新到 UI 里）
      // 所以这里通常还要：保证 cutIndex >= index，或者单独 patch parent
      const idxInSlice = slice.findIndex((m) => m.id === step.id);
      if (idxInSlice !== -1) {
        slice[idxInSlice] = {
          ...slice[idxInSlice],
          ...patch,
          steps: []
        };
      }
  
      return slice;
    });
  
    editMessage({
      ...step,
      ...patch
    });
  };
  

  const handleSaveOutput = () => {
    if (!draftOutput.trim()) return;
    commitStepPatch({ output: draftOutput });
    setIsEditingOutput(false);
  };

  const handleSaveInput = () => {
    if (!draftInput.trim()) return;

    // input 可能是 JSON
    let nextInput: any = draftInput;
    const originalWasString = typeof step.input === 'string';

    if (!originalWasString) {
      try {
        nextInput = JSON.parse(draftInput);
      } catch (e) {
        onError?.(new Error('Input 不是合法 JSON，无法保存'));
        console.error('Invalid JSON for step.input:', e);
        return;
      }
    }

    commitStepPatch({ input: nextInput } as any);
    setIsEditingInput(false);
  };

  return (
    <div className="ai-message flex gap-4 w-full">
      <Step step={step} isRunning={isRunning}>
        {/* input 区：加编辑按钮 */}
        {showInputSection ? (
          <div className="relative group w-full">
            {!isEditingInput ? (
              <>
                <MessageContent
                  elements={elements}
                  message={step}
                  allowHtml={allowHtml}
                  latex={latex}
                  sections={['input']}
                />

                {editable ? (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-1 right-1 invisible group-hover:visible"
                    onClick={() => {
                      // 每次点编辑时从当前 step.input 重新生成草稿，避免 stale
                      const v =
                        step.input == null
                          ? ''
                          : typeof step.input === 'string'
                          ? step.input
                          : JSON.stringify(step.input, null, 2);

                      setDraftInput(v);
                      setIsEditingInput(true);
                    }}
                    disabled={disabled}
                  >
                    <Pencil />
                  </Button>
                ) : null}
              </>
            ) : (
              <div className="w-full bg-accent rounded-xl p-3 flex flex-col gap-2">
                <AutoResizeTextarea
                  autoFocus
                  value={draftInput}
                  onChange={(e) => setDraftInput(e.target.value)}
                  maxHeight={300}
                  className="bg-transparent text-base font-mono"
                />

                <div className="flex justify-end gap-2">
                  <Button
                    variant="ghost"
                    onClick={() => {
                      const v =
                        step.input == null
                          ? ''
                          : typeof step.input === 'string'
                          ? step.input
                          : JSON.stringify(step.input, null, 2);

                      setDraftInput(v);
                      setIsEditingInput(false);
                    }}
                  >
                    取消
                  </Button>
                  <Button onClick={handleSaveInput} disabled={disabled}>
                    保存
                  </Button>
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* 子 steps：保持原逻辑 */}
        {childSteps.length ? (
          <Messages
            messages={childSteps}
            elements={elements}
            actions={actions}
            indent={indent + 1}
            isRunning={isRunning}
          />
        ) : null}

        {/* output 区：加编辑按钮 */}
        {shouldRenderOutput ? (
          <div className="relative group w-full">
            {!isEditingOutput ? (
              <>
                <MessageContent
                  ref={contentRef}
                  elements={elements}
                  message={step}
                  allowHtml={allowHtml}
                  latex={latex}
                  sections={showInputSection ? ['output'] : undefined}
                />

                {editable ? (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-1 right-1 invisible group-hover:visible"
                    onClick={() => {
                      setDraftOutput(step.output || '');
                      setIsEditingOutput(true);
                    }}
                    disabled={disabled}
                  >
                    <Pencil />
                  </Button>
                ) : null}
              </>
            ) : (
              <div className="w-full bg-accent rounded-xl p-3 flex flex-col gap-2">
                <AutoResizeTextarea
                  autoFocus
                  value={draftOutput}
                  onChange={(e) => setDraftOutput(e.target.value)}
                  maxHeight={300}
                  className="bg-transparent text-base"
                />

                <div className="flex justify-end gap-2">
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setDraftOutput(step.output || '');
                      setIsEditingOutput(false);
                    }}
                  >
                    取消
                  </Button>
                  <Button onClick={handleSaveOutput} disabled={disabled}>
                    保存
                  </Button>
                </div>
              </div>
            )}
          </div>
        ) : null}

        <MessageButtons message={step} actions={actions} contentRef={contentRef} />
      </Step>
    </div>
  );
});

export default StepMessage;
