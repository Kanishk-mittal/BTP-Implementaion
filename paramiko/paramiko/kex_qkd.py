"""
ETSI GS QKD 014 Key Exchange for SSH.

Implements Quantum Key Distribution (QKD) key agreement according to the
ETSI GS QKD 014 standard REST-based key delivery API.

In this key exchange method:
- Configuration (including master_sae_id and KME parameters) is loaded from a
  JSON configuration file (or defaults / environment variables).
- During communication, the target slave_sae_id can be obtained directly as
  input from the user (or passed into the transport/connect call).
- The SSH client acts as the Master SAE (Secure Application Entity) and requests
  a shared quantum key from its local Key Management Entity (KME).
- The client sends the UUID key_ID and SAE IDs to the SSH server in SSH_MSG_KEX_QKD_INIT.
- The SSH server acts as the Slave SAE and requests the matching quantum key
  from its local KME using the received key_ID and master_sae_id.
- Both sides use the synchronized quantum key material as the root shared
  secret K to compute the exchange hash H and derive symmetric session keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from paramiko.common import byte_chr
from paramiko.message import Message
from paramiko.ssh_exception import SSHException

if TYPE_CHECKING:
    from paramiko.transport import Transport

_MSG_KEX_QKD_INIT, _MSG_KEX_QKD_REPLY = range(30, 32)
c_MSG_KEX_QKD_INIT, c_MSG_KEX_QKD_REPLY = [
    byte_chr(c) for c in range(30, 32)
]


class QKDError(SSHException):
    """Exception raised for errors during QKD KME operations."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


@dataclass
class QKDConfig:
    """
    Configuration parameters for connecting to an ETSI GS QKD 014 KME.
    """

    kme_url: str = "http://localhost:8000"
    master_sae_id: str = "master-sae"
    slave_sae_id: Optional[str] = None
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    cafile: Optional[str] = None
    verify_tls: bool = True
    key_size: int = 256  # in bits (default 256 bits = 32 bytes)
    timeout: float = 5.0
    status_timeout: float = 1.0
    min_available_keys: int = 2  # min threshold of keys required in pool
    server_cert_file: Optional[str] = None  # CA-issued certificate for challenge-response
    server_key_file: Optional[str] = None  # CA-issued private key for challenge-response

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QKDConfig":
        """Create a QKDConfig instance from a dictionary."""
        return cls(
            kme_url=str(data.get("kme_url", "http://localhost:8000")).rstrip("/"),
            master_sae_id=str(data.get("master_sae_id", "master-sae")),
            slave_sae_id=data.get("slave_sae_id"),
            certfile=data.get("certfile"),
            keyfile=data.get("keyfile"),
            cafile=data.get("cafile"),
            verify_tls=bool(data.get("verify_tls", True)),
            key_size=int(data.get("key_size", 256)),
            timeout=float(data.get("timeout", 5.0)),
            status_timeout=float(data.get("status_timeout", 1.0)),
            min_available_keys=int(data.get("min_available_keys", 2)),
            server_cert_file=data.get("server_cert_file"),
            server_key_file=data.get("server_key_file"),
        )

    @classmethod
    def from_file(cls, path: Optional[Union[str, os.PathLike]] = None) -> "QKDConfig":
        """
        Load QKDConfig from a JSON configuration file.

        If path is not specified, searches the following in order:
        1. QKD_CONFIG_FILE environment variable (if set)
        2. ./qkd_config.json
        3. ~/.qkd/config.json
        4. /etc/qkd/config.json
        """
        if path is not None:
            resolved_path = os.path.expanduser(str(path))
            if not os.path.isfile(resolved_path):
                raise FileNotFoundError(f"QKD config file not found: {resolved_path}")
            with open(resolved_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)

        # Standard discovery locations
        candidates: List[str] = []
        env_file = os.environ.get("QKD_CONFIG_FILE")
        if env_file:
            candidates.append(os.path.expanduser(env_file))
        candidates.extend([
            "qkd_config.json",
            os.path.expanduser("~/.qkd/config.json"),
            "/etc/qkd/config.json",
        ])

        for cand in candidates:
            if os.path.isfile(cand):
                with open(cand, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return cls.from_dict(data)

        raise FileNotFoundError(
            f"No QKD config file found in candidate locations: {candidates}"
        )

    @classmethod
    def from_env(cls) -> "QKDConfig":
        """
        Create a QKDConfig populated from environment variables,
        falling back to default values.
        """
        verify_env = os.environ.get("QKD_VERIFY_TLS", "true").strip().lower()
        verify_tls = verify_env in ("1", "true", "yes", "on")

        try:
            key_size = int(os.environ.get("QKD_KEY_SIZE", "256"))
        except ValueError:
            key_size = 256

        try:
            timeout = float(os.environ.get("QKD_TIMEOUT", "5.0"))
        except ValueError:
            timeout = 5.0

        try:
            status_timeout = float(os.environ.get("QKD_STATUS_TIMEOUT", "1.0"))
        except ValueError:
            status_timeout = 1.0

        try:
            min_available_keys = int(os.environ.get("QKD_MIN_AVAILABLE_KEYS", "2"))
        except ValueError:
            min_available_keys = 2

        return cls(
            kme_url=os.environ.get("QKD_KME_URL", "http://localhost:8000").rstrip("/"),
            master_sae_id=os.environ.get("QKD_MASTER_SAE_ID", "master-sae"),
            slave_sae_id=os.environ.get("QKD_SLAVE_SAE_ID"),
            certfile=os.environ.get("QKD_CERT_FILE"),
            keyfile=os.environ.get("QKD_KEY_FILE"),
            cafile=os.environ.get("QKD_CA_FILE"),
            verify_tls=verify_tls,
            key_size=key_size,
            timeout=timeout,
            status_timeout=status_timeout,
            min_available_keys=min_available_keys,
            server_cert_file=os.environ.get("QKD_SERVER_CERT_FILE"),
            server_key_file=os.environ.get("QKD_SERVER_KEY_FILE"),
        )

    @classmethod
    def load(cls, config_source: Optional[Union[str, os.PathLike, dict, "QKDConfig"]] = None) -> "QKDConfig":
        """
        Load QKDConfig from a QKDConfig instance, dict, file path, or default config file.
        Falls back to environment variables if no config file is found.
        """
        if isinstance(config_source, QKDConfig):
            return config_source
        if isinstance(config_source, dict):
            return cls.from_dict(config_source)
        if isinstance(config_source, (str, os.PathLike)):
            return cls.from_file(config_source)

        try:
            return cls.from_file()
        except FileNotFoundError:
            return cls.from_env()

    def to_file(self, path: Union[str, os.PathLike]) -> None:
        """Save configuration to a JSON file."""
        data = {
            "kme_url": self.kme_url,
            "master_sae_id": self.master_sae_id,
            "slave_sae_id": self.slave_sae_id,
            "certfile": self.certfile,
            "keyfile": self.keyfile,
            "cafile": self.cafile,
            "verify_tls": self.verify_tls,
            "key_size": self.key_size,
            "timeout": self.timeout,
            "status_timeout": self.status_timeout,
            "min_available_keys": self.min_available_keys,
            "server_cert_file": self.server_cert_file,
            "server_key_file": self.server_key_file,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


class ETSIQKDClient:
    """
    Client implementation for the ETSI GS QKD 014 REST-based key delivery API.
    """

    def __init__(self, config: Optional[QKDConfig] = None, timeout: Optional[float] = None):
        self.config = config or QKDConfig.load()
        self.timeout = timeout if timeout is not None else self.config.timeout
        self._ssl_context = self._build_ssl_context()

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.config.kme_url.startswith("https://"):
            return None

        ctx = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=self.config.cafile,
        )

        if not self.config.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Mutual TLS: configure client certificate and private key if supplied
        if self.config.certfile:
            ctx.load_cert_chain(
                certfile=self.config.certfile,
                keyfile=self.config.keyfile,
            )

        return ctx

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.config.kme_url.rstrip('/')}{path}"
        data = None
        headers = {
            "Accept": "application/json",
        }

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                resp_bytes = resp.read()
                if not resp_bytes:
                    return {}
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            details = None
            msg = f"HTTP {exc.code} from KME: {exc.reason}"
            try:
                err_json = json.loads(err_body)
                if "message" in err_json:
                    msg = err_json["message"]
                details = err_json.get("details")
            except Exception:
                pass
            raise QKDError(f"KME request failed: {msg}", status_code=exc.code, details=details) from exc
        except urllib.error.URLError as exc:
            raise QKDError(f"Failed to connect to KME ({url}): {exc.reason}") from exc
        except Exception as exc:
            raise QKDError(f"Unexpected error communicating with KME: {exc}") from exc

    def get_status(self, slave_sae_id: Optional[str] = None) -> Dict[str, Any]:
        """
        ETSI GS QKD 014 Section 5.2: Get status
        GET https://{KME_hostname}/api/v1/keys/{slave_SAE_ID}/status
        """
        target_slave = slave_sae_id or self.config.slave_sae_id or "default"
        slave_id = urllib.parse.quote(target_slave, safe="")
        path = f"/api/v1/keys/{slave_id}/status"
        return self._request("GET", path)

    def get_key(
        self,
        slave_sae_id: Optional[str] = None,
        number: int = 1,
        size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        ETSI GS QKD 014 Section 5.3: Get key
        POST https://{KME_hostname}/api/v1/keys/{slave_SAE_ID}/enc_keys
        """
        target_slave = slave_sae_id or self.config.slave_sae_id
        if not target_slave:
            raise QKDError("slave_sae_id is required to request keys from KME")

        slave_id = urllib.parse.quote(target_slave, safe="")
        path = f"/api/v1/keys/{slave_id}/enc_keys"
        payload = {
            "number": number,
            "size": size or self.config.key_size,
        }
        return self._request("POST", path, payload)

    def get_challenge(self) -> Dict[str, Any]:
        """
        Custom extension: GET /api/v1/keys/challenge
        Request a challenge nonce from Slave KME before calling dec_keys.
        Returns: {"challenge": "<base64-nonce>", "challenge_id": "<uuid>"}
        """
        return self._request("GET", "/api/v1/keys/challenge")

    def get_key_with_key_ids(
        self,
        master_sae_id: Optional[str] = None,
        key_ids: Optional[List[str]] = None,
        challenge_id: Optional[str] = None,
        challenge_response: Optional[str] = None,
        sae_cert: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        ETSI GS QKD 014 Section 5.4: Get key with key IDs
        POST https://{KME_hostname}/api/v1/keys/{master_SAE_ID}/dec_keys
        with optional challenge-response proof parameters for Slave SAE authentication.
        """
        target_master = master_sae_id or self.config.master_sae_id
        if not target_master:
            raise QKDError("master_sae_id is required to fetch decryption keys from KME")

        master_id = urllib.parse.quote(target_master, safe="")
        path = f"/api/v1/keys/{master_id}/dec_keys"
        if not key_ids:
            raise QKDError("key_ids list cannot be empty for get_key_with_key_ids")

        payload: Dict[str, Any] = {
            "key_IDs": [{"key_ID": kid} for kid in key_ids]
        }
        if challenge_id:
            payload["challenge_id"] = challenge_id
        if challenge_response:
            payload["challenge_response"] = challenge_response
        if sae_cert:
            payload["sae_cert"] = sae_cert
        return self._request("POST", path, payload)


class KexQKD:
    """
    ``qkd-etsi014-sha256`` Key Exchange.

    Integrates ETSI GS QKD 014 Quantum Key Distribution into SSHv2 key agreement.
    The shared secret K is the synchronized quantum key delivered by the KME.
    """

    name = "qkd-etsi014-sha256"
    hash_algo = hashlib.sha256

    # Override for testing or environment control: None means check status endpoint
    _override_available: Optional[bool] = None

    def __init__(self, transport: Transport):
        self.transport = transport
        raw_config = getattr(transport, "qkd_config", None)
        self.config: QKDConfig = QKDConfig.load(raw_config)
        self.qkd_client = ETSIQKDClient(self.config)
        self.key_id: Optional[str] = None
        self.qkd_key: Optional[bytes] = None
        self.master_sae_id: Optional[str] = None
        self.slave_sae_id: Optional[str] = None
        self._c_init: Optional[bytes] = None

    @classmethod
    def set_available(cls, available: Optional[bool]) -> None:
        """Explicitly override availability status (useful for unit tests)."""
        cls._override_available = available

    @classmethod
    def is_available(cls, config: Optional[Union[QKDConfig, str, dict]] = None) -> bool:
        """
        Check if KME is available according to ETSI GS QKD 014 Section 5.2 (Get status).
        Returns True if the status endpoint responds successfully and stored_key_count >= min_available_keys.
        """
        if cls._override_available is not None:
            return cls._override_available

        try:
            cfg = QKDConfig.load(config)
            if not cfg.kme_url:
                return False
            client = ETSIQKDClient(cfg, timeout=cfg.status_timeout)
            status = client.get_status(cfg.slave_sae_id or "status-check")
            stored = status.get("stored_key_count", 0)
            threshold = cfg.min_available_keys
            if not isinstance(stored, int) or stored < threshold:
                import logging
                logging.getLogger("paramiko.transport").warning(
                    "[QKD] Key pool has %s key(s) (min threshold: %d) "
                    "— falling back to classical key exchange",
                    stored, threshold
                )
                return False
            return True
        except Exception:
            return False

    def _resolve_slave_sae_id(self) -> str:
        """
        Resolve the target slave_sae_id for communication:
        1. Explicitly passed attribute on Transport
        2. User input callback or interactive user prompt
        3. Fallback to default in configuration file
        """
        # Also auto-update master_sae_id from transport.qkd_username if set and default
        qkd_username = getattr(self.transport, "qkd_username", None)
        if qkd_username and (not self.config.master_sae_id or self.config.master_sae_id == "master-sae"):
            self.config.master_sae_id = qkd_username
            self.master_sae_id = qkd_username

        # 1. Transport-level attribute (passed e.g. via client.connect(..., slave_sae_id=...))
        slave_sae_id = getattr(self.transport, "slave_sae_id", None)
        if slave_sae_id:
            return str(slave_sae_id)

        default_slave = getattr(self.config, "slave_sae_id", None)

        # 2. Custom prompt function on Transport
        prompt_func: Optional[Callable[[str], str]] = getattr(
            self.transport, "slave_sae_id_prompt_func", None
        )
        prompt_enabled = getattr(self.transport, "prompt_for_slave_sae_id", True)

        if prompt_func is not None:
            prompt_msg = (
                f"Enter Slave SAE ID [{default_slave}]: "
                if default_slave
                else "Enter Slave SAE ID: "
            )
            val = prompt_func(prompt_msg).strip()
            if val:
                return val
            if default_slave:
                return str(default_slave)

        # 3. Interactive prompt via builtins.input if enabled and no default is present
        if prompt_enabled and default_slave is None:
            try:
                val = input("Enter target Slave SAE ID for QKD: ").strip()
                if val:
                    return val
            except (EOFError, OSError):
                pass

        # 4. Fallback to config file default
        if default_slave:
            return str(default_slave)

        raise SSHException(
            "Slave SAE ID is required for QKD key exchange but none was provided."
        )

    def _fetch_key_with_challenge(self, master_sae_id: str, key_id: str) -> Dict[str, Any]:
        """
        Authenticate to Slave KME via challenge-response if configured, then fetch quantum key.
        If server_key_file and server_cert_file are not configured, calls get_key_with_key_ids directly.
        """
        server_key_path = self.config.server_key_file
        server_cert_path = self.config.server_cert_file

        if not server_key_path or not server_cert_path:
            return self.qkd_client.get_key_with_key_ids(
                master_sae_id=master_sae_id, key_ids=[key_id]
            )

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            chall_data = self.qkd_client.get_challenge()
        except Exception as exc:
            raise SSHException(f"KME challenge request failed: {exc}") from exc

        challenge_b64 = chall_data.get("challenge")
        challenge_id = chall_data.get("challenge_id")
        if not challenge_b64 or not challenge_id:
            raise SSHException("KME returned malformed challenge response")

        try:
            nonce = base64.b64decode(challenge_b64)
        except Exception as exc:
            raise SSHException(f"Failed to decode KME challenge nonce: {exc}") from exc

        try:
            with open(server_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as exc:
            raise SSHException(f"Failed to load server private key for challenge: {exc}") from exc

        sig = private_key.sign(
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        try:
            with open(server_cert_path, "rb") as f:
                cert_pem_bytes = f.read()
        except Exception as exc:
            raise SSHException(f"Failed to load server certificate for challenge: {exc}") from exc

        return self.qkd_client.get_key_with_key_ids(
            master_sae_id=master_sae_id,
            key_ids=[key_id],
            challenge_id=challenge_id,
            challenge_response=base64.b64encode(sig).decode("ascii"),
            sae_cert=base64.b64encode(cert_pem_bytes).decode("ascii"),
        )

    # ---- protocol entry points ---------------------------------------

    def start_kex(self) -> None:
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEX_QKD_INIT)
            return

        # Client mode: Master SAE requests key from local KME
        slave_sae_id = self._resolve_slave_sae_id()
        self.slave_sae_id = slave_sae_id
        master_sae_id = self.config.master_sae_id
        self.master_sae_id = master_sae_id

        try:
            res = self.qkd_client.get_key(
                slave_sae_id=slave_sae_id,
                number=1,
                size=self.config.key_size,
            )
        except Exception as exc:
            raise SSHException(f"QKD client failed to obtain key from KME: {exc}") from exc

        keys = res.get("keys", [])
        if not keys:
            raise SSHException("QKD KME returned empty key container")

        first_key = keys[0]
        self.key_id = first_key.get("key_ID")
        key_b64 = first_key.get("key")
        if not self.key_id or not key_b64:
            raise SSHException("Invalid QKD key container format (missing key_ID or key)")

        try:
            self.qkd_key = base64.b64decode(key_b64)
        except Exception as exc:
            raise SSHException(f"Failed to base64-decode QKD key: {exc}") from exc

        # Construct and send SSH_MSG_KEX_QKD_INIT
        c_init = self.key_id.encode("utf-8")
        self._c_init = c_init

        m = Message()
        m.add_byte(c_MSG_KEX_QKD_INIT)
        m.add_string(c_init)
        # Send master_sae_id and slave_sae_id so server knows who called and who it is
        m.add_string(master_sae_id.encode("utf-8"))
        m.add_string(slave_sae_id.encode("utf-8"))
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEX_QKD_REPLY)

    def parse_next(self, ptype: int, m: Message) -> None:
        if self.transport.server_mode and ptype == _MSG_KEX_QKD_INIT:
            return self._parse_qkd_init(m)
        if not self.transport.server_mode and ptype == _MSG_KEX_QKD_REPLY:
            return self._parse_qkd_reply(m)
        raise SSHException(
            "{} asked to handle packet type {:d}".format(
                self.__class__.__name__, ptype
            )
        )

    # ---- server side -------------------------------------------------

    def _parse_qkd_init(self, m: Message) -> None:
        c_init = m.get_string()
        try:
            key_id = c_init.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SSHException("Malformed QKD key_ID in KEX init") from exc

        self.key_id = key_id

        # Read master_sae_id and slave_sae_id if sent by client
        if len(m.get_remainder()) > 0:
            master_sae_id = m.get_text()
        else:
            master_sae_id = self.config.master_sae_id

        if len(m.get_remainder()) > 0:
            slave_sae_id = m.get_text()
        else:
            slave_sae_id = getattr(self.config, "slave_sae_id", None)

        self.master_sae_id = master_sae_id
        self.slave_sae_id = slave_sae_id

        # Server mode: Slave SAE retrieves identical key from local KME using received master_sae_id
        # (with challenge-response authentication if server cert/key are configured)
        try:
            res = self._fetch_key_with_challenge(
                master_sae_id=master_sae_id,
                key_id=key_id,
            )
        except Exception as exc:
            raise SSHException(f"QKD server failed to fetch key from KME: {exc}") from exc

        keys = res.get("keys", [])
        if not keys:
            raise SSHException(f"QKD KME returned no matching key for key_ID {key_id}")

        first_key = keys[0]
        key_b64 = first_key.get("key")
        if not key_b64:
            raise SSHException("QKD KME returned missing key material")

        try:
            K_bytes = base64.b64decode(key_b64)
        except Exception as exc:
            raise SSHException(f"Failed to base64-decode QKD key on server: {exc}") from exc

        self.qkd_key = K_bytes

        # Server generates a random 32-byte nonce as confirmation/reply payload
        s_reply = os.urandom(32)

        K_S = self.transport.get_server_key().asbytes()

        hm = Message()
        hm.add(
            self.transport.remote_version,
            self.transport.local_version,
            self.transport.remote_kex_init,
            self.transport.local_kex_init,
        )
        hm.add_string(K_S)
        hm.add_string(c_init)
        hm.add_string(s_reply)
        hm.add_string(K_bytes)
        H = self.hash_algo(hm.asbytes()).digest()

        self.transport._set_K_H(K_bytes, H)

        sig = self.transport.get_server_key().sign_ssh_data(
            H, self.transport.host_key_type
        )

        reply = Message()
        reply.add_byte(c_MSG_KEX_QKD_REPLY)
        reply.add_string(K_S)
        reply.add_string(s_reply)
        reply.add_string(sig)
        self.transport._send_message(reply)
        self.transport._activate_outbound()

    # ---- client side -------------------------------------------------

    def _parse_qkd_reply(self, m: Message) -> None:
        K_S = m.get_string()
        s_reply = m.get_string()
        sig = m.get_binary()

        K_bytes = self.qkd_key
        if K_bytes is None:
            raise SSHException("QKD client state missing quantum key material")

        c_init = self._c_init
        if c_init is None:
            raise SSHException("QKD client state missing c_init payload")

        hm = Message()
        hm.add(
            self.transport.local_version,
            self.transport.remote_version,
            self.transport.local_kex_init,
            self.transport.remote_kex_init,
        )
        hm.add_string(K_S)
        hm.add_string(c_init)
        hm.add_string(s_reply)
        hm.add_string(K_bytes)
        H = self.hash_algo(hm.asbytes()).digest()

        self.transport._set_K_H(K_bytes, H)
        self.transport._verify_key(K_S, sig)
        self.transport._activate_outbound()
