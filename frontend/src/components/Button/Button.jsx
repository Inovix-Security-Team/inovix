import "./Button.css";

function Button({
  children,
  variant = "primary",
  disabled = false,
  type = "button",
  onClick,
}) {
  return (
    <button
      type={type}
      className={`button button-${variant}`}
      disabled={disabled}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

export default Button;