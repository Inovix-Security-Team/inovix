import "./LoadingIndicator.css";

function LoadingIndicator({ message = "Loading..." }) {
  return (
    <div className="loading-container" role="status" aria-live="polite">
      <div className="loading-spinner"></div>
      <span>{message}</span>
    </div>
  );
}

export default LoadingIndicator;