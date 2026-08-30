import "./Input.css";

function Input({
  label,
  placeholder,
  value,
  onChange,
  error,
  disabled = false,
  type = "text",
}) {
  return (
    <div className="input-wrapper">
      {label && <label className="input-label">{label}</label>}

      <input
        className={`input-field ${error ? "input-error" : ""}`}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        disabled={disabled}
      />

      {error && <p className="input-error-message">{error}</p>}
    </div>
  );
}

export default Input;