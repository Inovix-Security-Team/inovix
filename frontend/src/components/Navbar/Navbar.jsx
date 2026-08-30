import "./Navbar.css";

function Navbar({ items = [], logo = "INOVIX" }) {
  return (
    <nav className="navbar">
      <div className="navbar-logo">{logo}</div>

      <div className="navbar-links">
        {items.map((item, index) => (
          <a
            key={index}
            href={item.href || "#"}
            className="navbar-link"
          >
            {item.label}
          </a>
        ))}
      </div>
    </nav>
  );
}

export default Navbar;