import "./ErrorMessage.css";

function ErrorMessage({ message = "Something went wrong." }) {
  return (
    <div className="error-message" role="alert">
      <span className="error-icon">!</span>
      <span>{message}</span>
    </div>
  );
}

export default ErrorMessage;