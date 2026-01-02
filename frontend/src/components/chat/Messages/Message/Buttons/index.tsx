import {
  IAction,
  type IStep,
  useChatMessages,
  useConfig,
  useChatInteract
} from '@chainlit/react-client';

import { RefreshCw } from 'lucide-react';
import { useContext } from 'react';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger
} from '@/components/ui/tooltip';

import CopyButton from '@/components/CopyButton';
import { MessageContext } from '@/contexts/MessageContext';

import MessageActions from './Actions';
import { DebugButton } from './DebugButton';
import { FeedbackButtons } from './FeedbackButtons';

interface Props {
  message: IStep;
  actions: IAction[];
  run?: IStep;
  contentRef?: React.RefObject<HTMLDivElement>;
}

const MessageButtons = ({ message, actions, run, contentRef }: Props) => {
  const { config } = useConfig();
  const { firstInteraction } = useChatMessages();
  const { regenerateMessage } = useChatInteract();
  const { loading, askUser } = useContext(MessageContext);

  const isUser = message.type === 'user_message';
  const isAsk = message.waitForAnswer;
  const hasContent = !!message.output;
  const showCopyButton = !!run && hasContent && !isUser && !isAsk;
  
  // Show regenerate button for assistant messages that have content and are not streaming
  const showRegenerateButton = !isUser && hasContent && !message.streaming && !!run;

  const messageActions = actions.filter((a) => a.forId === message.id);

  const showDebugButton =
    !!config?.debugUrl && !!message.threadId && !!firstInteraction && !!run;

  const show = showCopyButton || showRegenerateButton || showDebugButton || messageActions?.length;

  if (!show || message.streaming) {
    return null;
  }

  // Disable regenerate button when loading or asking user (similar to UserMessage)
  // const disabled = loading;

  const handleRegenerate = () => {
    regenerateMessage(message);
  };

  return (
    <div className="-ml-1.5 flex items-center flex-wrap">
      {showRegenerateButton ? (
        <TooltipProvider delayDuration={100}>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                onClick={handleRegenerate}
                className="text-muted-foreground"
                disabled={false}
              >
                <RefreshCw className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>重新生成</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ) : null}
      {showCopyButton ? (
        <CopyButton content={message.output} contentRef={contentRef} />
      ) : null}
      {run ? <FeedbackButtons message={run} /> : null}
      {messageActions.length ? (
        <MessageActions actions={messageActions} />
      ) : null}
      {showDebugButton ? (
        <DebugButton debugUrl={config.debugUrl!} step={message} />
      ) : null}
    </div>
  );
};

export { MessageButtons };
