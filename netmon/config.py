import json
import os
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_PATH = Path("/etc/netmon/config.json")


def load_config(config_path: Optional[str] = None) -> dict:
    path = config_path or os.environ.get("NETMON_CONFIG")

    if path:
        p = Path(path)
    else:
        p = DEFAULT_CONFIG_PATH

    config = {
        "host": "0.0.0.0",
        "port": 8000,
        "jwt_secret": None,
        "jwt_expire_hours": 24,
        "log_level": "info",
        "openvpn_management_host": "127.0.0.1",
        "openvpn_management_port": 5555,
    }

    if p.exists():
        with open(p) as f:
            user_config = json.load(f)
            config.update(user_config)

    if config["jwt_secret"] is None:
        import hashlib
        config["jwt_secret"] = hashlib.sha256(os.urandom(64)).hexdigest()

    return config
