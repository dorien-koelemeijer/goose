import { useState } from 'react';
import { Shield, AlertTriangle, XCircle } from 'lucide-react';

// Temporary API function - this should be moved to a proper API file
const confirmSecurityPermission = async ({ body }: { body: { id: string; permission: string; threat_level: string } }) => {
  try {
    const response = await fetch('/api/security/confirm', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    
    if (!response.ok) {
      return { error: `HTTP error! status: ${response.status}` };
    }
    
    return { success: true };
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Unknown error' };
  }
};

const ALLOW_ONCE = 'allow_once';
const DENY_ONCE = 'deny_once';
const ALWAYS_ALLOW = 'always_allow';
const NEVER_ALLOW = 'never_allow';

interface SecurityConfirmationProps {
  isCancelledMessage: boolean;
  isClicked: boolean;
  securityConfirmationId: string;
  threatLevel: string;
  explanation: string;
  originalContent: string;
  prompt?: string;
}

export default function SecurityConfirmation({
  isCancelledMessage,
  isClicked,
  securityConfirmationId,
  threatLevel,
  explanation,
  originalContent,
  prompt,
}: SecurityConfirmationProps) {
  const [clicked, setClicked] = useState(isClicked);
  const [status, setStatus] = useState('unknown');
  const [actionDisplay, setActionDisplay] = useState('');

  const handleButtonClick = async (action: string) => {
    setClicked(true);
    setStatus(action);
    
    if (action === ALWAYS_ALLOW) {
      setActionDisplay('always allowed');
    } else if (action === ALLOW_ONCE) {
      setActionDisplay('allowed once');
    } else if (action === DENY_ONCE) {
      setActionDisplay('denied once');
    } else if (action === NEVER_ALLOW) {
      setActionDisplay('never allowed');
    }

    try {
      const response = await confirmSecurityPermission({
        body: { 
          id: securityConfirmationId, 
          permission: action,
          threat_level: threatLevel
        },
      });
      if (response.error) {
        console.error('Failed to confirm security permission: ', response.error);
      }
    } catch (err) {
      console.error('Error confirming security permission:', err);
    }
  };

  const getThreatIcon = () => {
    switch (threatLevel.toLowerCase()) {
      case 'critical':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'high':
        return <AlertTriangle className="w-5 h-5 text-orange-500" />;
      case 'medium':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'low':
        return <Shield className="w-5 h-5 text-blue-500" />;
      default:
        return <Shield className="w-5 h-5 text-gray-500" />;
    }
  };

  const getThreatColor = () => {
    switch (threatLevel.toLowerCase()) {
      case 'critical':
        return 'text-red-600 dark:text-red-400';
      case 'high':
        return 'text-orange-600 dark:text-orange-400';
      case 'medium':
        return 'text-yellow-600 dark:text-yellow-400';
      case 'low':
        return 'text-blue-600 dark:text-blue-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  return isCancelledMessage ? (
    <div className="goose-message-content bg-bgSubtle rounded-2xl px-4 py-2 text-textStandard">
      Security confirmation is cancelled.
    </div>
  ) : (
    <>
      <div className="goose-message-content bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-2xl px-4 py-3 rounded-b-none">
        <div className="flex items-start space-x-3">
          {getThreatIcon()}
          <div className="flex-1">
            <div className="flex items-center space-x-2 mb-2">
              <h4 className={`font-semibold ${getThreatColor()}`}>
                Security Alert - {threatLevel} Threat Detected
              </h4>
            </div>
            <p className="text-textStandard text-sm mb-3">
              {explanation}
            </p>
            {prompt && (
              <p className="text-textStandard text-sm font-medium">
                {prompt}
              </p>
            )}
            {originalContent && (
              <details className="mt-3">
                <summary className="text-textStandard text-sm cursor-pointer hover:text-textProminent">
                  View detected content
                </summary>
                <div className="mt-2 p-3 bg-gray-100 dark:bg-gray-800 rounded text-sm font-mono text-textStandard whitespace-pre-wrap max-h-32 overflow-y-auto">
                  {originalContent}
                </div>
              </details>
            )}
          </div>
        </div>
      </div>
      
      {clicked ? (
        <div className="goose-message-tool bg-bgApp border border-borderSubtle dark:border-gray-700 rounded-b-2xl px-4 pt-2 pb-2 flex items-center justify-between">
          <div className="flex items-center">
            {(status === ALWAYS_ALLOW || status === ALLOW_ONCE) && (
              <svg
                className="w-5 h-5 text-green-500"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            )}
            {(status === DENY_ONCE || status === NEVER_ALLOW) && (
              <svg
                className="w-5 h-5 text-red-500"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            )}
            <span className="ml-2 text-textStandard">
              {isClicked
                ? 'Security confirmation is not available'
                : `Content is ${actionDisplay}`}
            </span>
          </div>
        </div>
      ) : (
        <div className="goose-message-tool bg-bgApp border border-borderSubtle dark:border-gray-700 rounded-b-2xl px-4 pt-2 pb-2">
          <div className="flex flex-col gap-2">
            <div className="flex gap-2">
              <button
                className="bg-green-600 hover:bg-green-700 text-white rounded-full px-4 py-2 text-sm transition"
                onClick={() => handleButtonClick(ALLOW_ONCE)}
              >
                Allow Once
              </button>
              <button
                className="bg-red-600 hover:bg-red-700 text-white rounded-full px-4 py-2 text-sm transition"
                onClick={() => handleButtonClick(DENY_ONCE)}
              >
                Deny Once
              </button>
            </div>
            <div className="flex gap-2">
              <button
                className="bg-green-500 hover:bg-green-600 text-white rounded-full px-4 py-2 text-sm transition"
                onClick={() => handleButtonClick(ALWAYS_ALLOW)}
              >
                Always Allow ({threatLevel})
              </button>
              <button
                className="bg-red-500 hover:bg-red-600 text-white rounded-full px-4 py-2 text-sm transition"
                onClick={() => handleButtonClick(NEVER_ALLOW)}
              >
                Never Allow ({threatLevel})
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}