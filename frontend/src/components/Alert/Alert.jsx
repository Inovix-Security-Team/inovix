import "./Alert.css";

function Alert({ type = "info", message }) {
  return (
    <div className={`alert alert-${type}`} role="alert">
      <span className="alert-icon">
        {type === "success" && "✓"}
        {type === "warning" && "!"}
        {type === "error" && "×"}
        {type === "info" && "i"}
      </span>

      <span>{message}</span>
    </div>
  );
}

export default Alert;