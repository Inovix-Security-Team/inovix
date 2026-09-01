import psutil


def snapshot() -> dict:
    """Return a snapshot of active internet connections."""

    connections = []

    try:
        for connection in psutil.net_connections(kind="inet"):
            local = (
                f"{connection.laddr.ip}:{connection.laddr.port}"
                if connection.laddr
                else "-"
            )

            remote = (
                f"{connection.raddr.ip}:{connection.raddr.port}"
                if connection.raddr
                else "-"
            )

            connections.append(
                {
                    "pid": connection.pid,
                    "local": local,
                    "remote": remote,
                    "status": connection.status,
                }
            )

    except (psutil.AccessDenied, OSError):
        pass

    return {
        "count": len(connections),
        "connections": connections[:30],
    }