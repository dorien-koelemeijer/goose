import { useState } from 'react';
import { SecurityNoteContent } from '../types/message';
import { submitSecurityFeedback } from '../api/sdk.gen';

interface SecurityNoteProps {
  note: SecurityNoteContent;
}

// Convert technical explanation to user-friendly message
const getSimplifiedExplanation = (explanation: string): string => {
  // Check for common patterns and provide user-friendly messages
  if (explanation.toLowerCase().includes('prompt injection')) {
    return "Your message appears to contain instructions that could interfere with Goose's normal operation. Your feedback helps us improve our detection accuracy.";
  }

  if (explanation.toLowerCase().includes('malicious content')) {
    return 'This content was flagged as potentially harmful. If you believe this is incorrect, please let us know using the feedback buttons below.';
  }

  if (explanation.toLowerCase().includes('ensemble result')) {
    return 'Our security models detected potential risks in your message. Your feedback is valuable for improving our accuracy and reducing false positives.';
  }

  if (explanation.toLowerCase().includes('tool')) {
    return 'The requested action was flagged for security review. Help us learn by indicating whether this detection was correct.';
  }

  // Default fallback with encouragement for feedback
  return 'This content triggered our security filters. Your feedback helps us balance security with usability - please let us know if this seems incorrect.';
};

export default function SecurityNote({ note }: SecurityNoteProps) {
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const [showCommentBox, setShowCommentBox] = useState(false);
  const [comment, setComment] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleFeedback = async (
    feedbackType: 'false_positive' | 'missed_threat' | 'correct_flag' | 'other'
  ) => {
    if (feedbackSubmitted) return;

    setIsSubmitting(true);
    try {
      await submitSecurityFeedback({
        throwOnError: true,
        body: {
          note_id: note.findingId,
          feedback_type: feedbackType,
          user_comment: comment.trim() || undefined,
        },
      });
      setFeedbackSubmitted(true);
      console.log(`Security feedback submitted: ${feedbackType} for finding ${note.findingId}`);
    } catch (error) {
      console.error('Failed to submit security feedback:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCommentSubmit = () => {
    if (comment.trim()) {
      // Submit with "other" feedback type when user provides a comment
      handleFeedback('other');
    }
    setShowCommentBox(false);
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'low':
        return 'text-yellow-600 dark:text-yellow-400';
      case 'medium':
        return 'text-orange-600 dark:text-orange-400';
      case 'high':
        return 'text-red-600 dark:text-red-400';
      case 'critical':
        return 'text-red-800 dark:text-red-300';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  const getThreatLevelIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'low':
        return '⚠️';
      case 'medium':
        return '🔶';
      case 'high':
        return '🚨';
      case 'critical':
        return '🔴';
      default:
        return '🔒';
    }
  };

  return (
    <div className="mt-3 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
      <div className="flex items-start gap-2">
        <span className="text-lg">{getThreatLevelIcon(note.threatLevel)}</span>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Security Detection
            </span>
            <span
              className={`text-xs font-semibold uppercase ${getThreatLevelColor(note.threatLevel)}`}
            >
              {note.threatLevel}
            </span>
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
            {/* Show a user-friendly version of the explanation */}
            {getSimplifiedExplanation(note.explanation)}
          </p>

          {note.showFeedbackOptions && !feedbackSubmitted && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-gray-500 dark:text-gray-500">Help us improve:</span>

              <button
                onClick={() => handleFeedback('correct_flag')}
                disabled={isSubmitting}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-green-100 hover:bg-green-200 dark:bg-green-900/30 dark:hover:bg-green-900/50 text-green-700 dark:text-green-300 rounded transition-colors disabled:opacity-50"
              >
                👍 Correct
              </button>

              <button
                onClick={() => handleFeedback('false_positive')}
                disabled={isSubmitting}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/50 text-red-700 dark:text-red-300 rounded transition-colors disabled:opacity-50"
              >
                👎 False Positive
              </button>

              <button
                onClick={() => setShowCommentBox(!showCommentBox)}
                disabled={isSubmitting}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:hover:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded transition-colors disabled:opacity-50"
              >
                💬 Comment
              </button>
            </div>
          )}

          {showCommentBox && !feedbackSubmitted && (
            <div className="mt-2 space-y-2">
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Add your feedback about this security detection..."
                className="w-full px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 resize-none"
                rows={2}
              />
              <div className="flex gap-2">
                <button
                  onClick={handleCommentSubmit}
                  disabled={isSubmitting || !comment.trim()}
                  className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors disabled:opacity-50"
                >
                  Submit
                </button>
                <button
                  onClick={() => {
                    setShowCommentBox(false);
                    setComment('');
                  }}
                  className="px-2 py-1 text-xs bg-gray-300 hover:bg-gray-400 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {feedbackSubmitted && (
            <div className="text-xs text-green-600 dark:text-green-400 mt-2">
              ✅ Thank you! Your feedback helps us improve Goose's security accuracy.
            </div>
          )}

          <div className="text-xs text-gray-400 dark:text-gray-500 mt-2">
            {new Date(note.timestamp).toLocaleString()}
          </div>
        </div>
      </div>
    </div>
  );
}
