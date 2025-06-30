import { useState, useEffect } from 'react';
import GooseLogo from './GooseLogo';

interface MessageContent {
  type: string;
  text?: string;
}

interface Message {
  role: string;
  content: MessageContent[];
}

interface LoadingGooseProps {
  messages?: Message[]; // Array of messages to check for security setup
}

const LoadingGoose = ({ messages = [] }: LoadingGooseProps) => {
  const [showSetupMessage, setShowSetupMessage] = useState(false);

  // Check if we're in a security setup scenario
  const hasSecuritySetupMessage =
    messages.length > 0 &&
    messages.slice(-5).some(
      (
        message: Message // Check last 5 messages
      ) =>
        message?.role === 'assistant' &&
        message?.content?.some(
          (content: MessageContent) =>
            content.type === 'text' &&
            (content.text?.includes('Goose is being set up') ||
              content.text?.includes('Security models will be initialized') ||
              content.text?.includes('this could take up to a minute') ||
              content.text?.includes('Security System Ready'))
        )
    );

  // Use a timeout to detect long-running operations (likely model downloads)
  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout> | undefined;

    // Count only user messages to determine if this is first or second user interaction
    const userMessageCount = messages.filter((message: Message) => message?.role === 'user').length;

    if (userMessageCount <= 2) {
      // For first or second user messages, wait 10 seconds before assuming it's setup
      timeout = setTimeout(() => {
        setShowSetupMessage(true);
      }, 10000);
    }

    return () => {
      if (timeout) {
        clearTimeout(timeout);
      }
      setShowSetupMessage(false);
    };
  }, [messages]);

  // Determine what message to show
  const isPossiblySecuritySetup = hasSecuritySetupMessage || showSetupMessage;

  const loadingText = isPossiblySecuritySetup
    ? 'goose is being set up, this could take up to a minute…'
    : 'goose is working on it…';

  return (
    <div className="w-full pb-[2px]">
      <div
        data-testid="loading-indicator"
        className="flex items-center text-xs text-textStandard mb-2 mt-2 animate-[appear_250ms_ease-in_forwards]"
      >
        <GooseLogo className="mr-2" size="small" hover={false} />
        {loadingText}
      </div>
    </div>
  );
};

export default LoadingGoose;
