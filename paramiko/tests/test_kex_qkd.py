import base64
import json
import os
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
from paramiko import Message, RSAKey, Transport
from paramiko.kex_qkd import (
    ETSIQKDClient,
    KexQKD,
    QKDConfig,
    QKDError,
    _MSG_KEX_QKD_INIT,
    _MSG_KEX_QKD_REPLY,
)
from paramiko.ssh_exception import SSHException

from ._loop import LoopSocket
from ._util import TestServer, _support


class MockKMEHandler(BaseHTTPRequestHandler):
    keys_db = {}
    stored_key_count = 100
    fail_status = False
    fail_enc_keys = False
    fail_dec_keys = False
    last_enc_slave_id = None
    last_dec_master_id = None

    def log_message(self, format, *args):
        # Silence HTTP server logging during tests
        pass

    def _send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "/status" in self.path:
            if self.fail_status:
                self._send_json(503, {"message": "KME service unavailable"})
                return
            self._send_json(200, {
                "source_KME_ID": "KME_A",
                "target_KME_ID": "KME_B",
                "master_SAE_ID": "master-sae",
                "slave_SAE_ID": "slave-sae",
                "key_size": 256,
                "stored_key_count": self.stored_key_count,
                "max_key_count": 10000,
                "max_key_per_request": 10,
                "max_key_size": 1024,
                "min_key_size": 64,
                "max_SAE_ID_count": 0,
            })
        if "/challenge" in self.path:
            MockKMEHandler.challenge_requested = True
            nonce = os.urandom(32)
            self._send_json(200, {
                "challenge": base64.b64encode(nonce).decode("ascii"),
                "challenge_id": "test-challenge-id-1234",
            })
            return
        self._send_json(404, {"message": "Not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)
        req_data = json.loads(post_body.decode("utf-8")) if post_body else {}

        if "/enc_keys" in self.path:
            # Extract slave_sae_id from path
            # /api/v1/keys/{slave_sae_id}/enc_keys
            parts = self.path.split("/")
            if len(parts) >= 5:
                MockKMEHandler.last_enc_slave_id = parts[4]

            if self.fail_enc_keys:
                self._send_json(400, {"message": "Key generation failed in KME"})
                return
            kid = str(uuid.uuid4())
            key_material = os.urandom(32)  # 256-bit key
            self.keys_db[kid] = key_material
            self._send_json(200, {
                "keys": [
                    {
                        "key_ID": kid,
                        "key": base64.b64encode(key_material).decode("ascii"),
                    }
                ]
            })
            return

        if "/dec_keys" in self.path:
            # Extract master_sae_id from path
            # /api/v1/keys/{master_sae_id}/dec_keys
            parts = self.path.split("/")
            if len(parts) >= 5:
                MockKMEHandler.last_dec_master_id = parts[4]

            MockKMEHandler.last_challenge_id = req_data.get("challenge_id")
            MockKMEHandler.last_challenge_response = req_data.get("challenge_response")
            MockKMEHandler.last_sae_cert = req_data.get("sae_cert")

            if self.fail_dec_keys:
                self._send_json(400, {"message": "Decryption key lookup failed"})
                return
            req_ids = req_data.get("key_IDs", [])
            returned_keys = []
            for item in req_ids:
                kid = item.get("key_ID")
                if kid in self.keys_db:
                    returned_keys.append({
                        "key_ID": kid,
                        "key": base64.b64encode(self.keys_db[kid]).decode("ascii"),
                    })
                else:
                    self._send_json(400, {"message": f"Key {kid} not found on KME"})
                    return

            self._send_json(200, {"keys": returned_keys})
            return

        self._send_json(404, {"message": "Not found"})


class TestKexQKD(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockKMEHandler.keys_db = {}
        MockKMEHandler.stored_key_count = 100
        MockKMEHandler.fail_status = False
        MockKMEHandler.fail_enc_keys = False
        MockKMEHandler.fail_dec_keys = False
        MockKMEHandler.last_enc_slave_id = None
        MockKMEHandler.last_dec_master_id = None
        MockKMEHandler.challenge_requested = False
        MockKMEHandler.last_challenge_id = None
        MockKMEHandler.last_challenge_response = None
        MockKMEHandler.last_sae_cert = None

        cls.httpd = HTTPServer(("127.0.0.1", 0), MockKMEHandler)
        cls.port = cls.httpd.server_address[1]
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        cls.kme_url = f"http://127.0.0.1:{cls.port}"
        cls.config = QKDConfig(
            kme_url=cls.kme_url,
            master_sae_id="client-sae",
            slave_sae_id="server-sae",
            key_size=256,
            timeout=2.0,
            status_timeout=1.0,
        )

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.server_thread.join()

    def setUp(self):
        MockKMEHandler.stored_key_count = 100
        MockKMEHandler.fail_status = False
        MockKMEHandler.fail_enc_keys = False
        MockKMEHandler.fail_dec_keys = False
        MockKMEHandler.last_enc_slave_id = None
        MockKMEHandler.last_dec_master_id = None
        MockKMEHandler.challenge_requested = False
        MockKMEHandler.last_challenge_id = None
        MockKMEHandler.last_challenge_response = None
        MockKMEHandler.last_sae_cert = None
        KexQKD.set_available(None)

    def test_qkd_config_file_save_and_load(self):
        """Test that master_sae_id and KME parameters can be loaded from a config file."""
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            config_data = {
                "kme_url": self.kme_url,
                "master_sae_id": "config-master-sae-99",
                "slave_sae_id": None,
                "key_size": 256,
                "timeout": 3.5,
                "status_timeout": 1.2,
                "verify_tls": False,
            }
            json.dump(config_data, tf)
            temp_path = tf.name

        try:
            cfg = QKDConfig.from_file(temp_path)
            self.assertEqual(cfg.kme_url, self.kme_url)
            self.assertEqual(cfg.master_sae_id, "config-master-sae-99")
            self.assertIsNone(cfg.slave_sae_id)
            self.assertEqual(cfg.timeout, 3.5)
            self.assertFalse(cfg.verify_tls)

            loaded = QKDConfig.load(temp_path)
            self.assertEqual(loaded.master_sae_id, "config-master-sae-99")
        finally:
            os.remove(temp_path)

    def test_qkd_client_status(self):
        client = ETSIQKDClient(self.config)
        status = client.get_status("server-sae")
        self.assertEqual(status["stored_key_count"], 100)
        self.assertEqual(status["source_KME_ID"], "KME_A")

    def test_qkd_client_key_delivery(self):
        client = ETSIQKDClient(self.config)
        enc_res = client.get_key(slave_sae_id="server-sae", number=1, size=256)
        self.assertIn("keys", enc_res)
        self.assertEqual(len(enc_res["keys"]), 1)
        key_id = enc_res["keys"][0]["key_ID"]
        key_b64 = enc_res["keys"][0]["key"]

        dec_res = client.get_key_with_key_ids(master_sae_id="client-sae", key_ids=[key_id])
        self.assertIn("keys", dec_res)
        self.assertEqual(len(dec_res["keys"]), 1)
        self.assertEqual(dec_res["keys"][0]["key_ID"], key_id)
        self.assertEqual(dec_res["keys"][0]["key"], key_b64)

    def test_qkd_is_available(self):
        # When status succeeds and stored_key_count >= threshold (100 >= 2)
        self.assertTrue(KexQKD.is_available(self.config))

        # When stored_key_count is below threshold (1 < 2)
        MockKMEHandler.stored_key_count = 1
        self.assertFalse(KexQKD.is_available(self.config))

        # When threshold is configured to 1 (1 >= 1)
        cfg_thresh1 = QKDConfig(
            kme_url=self.kme_url,
            master_sae_id="client-sae",
            slave_sae_id="server-sae",
            min_available_keys=1,
            status_timeout=1.0,
        )
        self.assertTrue(KexQKD.is_available(cfg_thresh1))

        # When stored_key_count == 0
        MockKMEHandler.stored_key_count = 0
        self.assertFalse(KexQKD.is_available(self.config))

        # When status endpoint returns error
        MockKMEHandler.fail_status = True
        self.assertFalse(KexQKD.is_available(self.config))

        # When pointing to unreachable KME
        bad_config = QKDConfig(kme_url="http://127.0.0.1:1", status_timeout=0.2)
        self.assertFalse(KexQKD.is_available(bad_config))

    def test_qkd_set_available_override(self):
        KexQKD.set_available(True)
        self.assertTrue(KexQKD.is_available())
        KexQKD.set_available(False)
        self.assertFalse(KexQKD.is_available())
        KexQKD.set_available(None)

    def test_qkd_error_handling(self):
        MockKMEHandler.fail_enc_keys = True
        client = ETSIQKDClient(self.config)
        with self.assertRaises(QKDError) as cm:
            client.get_key("server-sae")
        self.assertEqual(cm.exception.status_code, 400)

    def test_kex_qkd_slave_sae_id_user_input(self):
        """
        Verify that slave_sae_id can be obtained interactively or via prompt function
        during key exchange communication.
        """
        prompted_messages = []

        def mock_user_input(prompt):
            prompted_messages.append(prompt)
            return "user-entered-slave-sae"

        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)

        # Config without slave_sae_id (only master_sae_id configured)
        client_config = QKDConfig(
            kme_url=self.kme_url,
            master_sae_id="client-master-from-config",
            slave_sae_id=None,
        )

        tc = Transport(
            sockc,
            qkd_config=client_config,
            slave_sae_id_prompt_func=mock_user_input,
        )
        ts = Transport(socks, qkd_config=client_config)

        host_key = RSAKey.from_private_key_file(_support("rsa.key"))

        try:
            for side in (tc, ts):
                side.get_security_options().kex = ("qkd-etsi014-sha256",)

            ts.add_server_key(host_key)
            event = threading.Event()
            ts.start_server(event, TestServer())

            tc.connect(
                hostkey=RSAKey(data=host_key.asbytes()),
                username="slowdive",
                password="pygmalion",
            )
            event.wait(2.0)

            self.assertTrue(event.is_set())
            self.assertTrue(ts.is_active())
            self.assertTrue(tc.is_authenticated())

            # Verify that user input was requested
            self.assertEqual(len(prompted_messages), 1)
            self.assertIn("Enter Slave SAE ID", prompted_messages[0])

            # Verify that client used the entered slave_sae_id to request keys
            self.assertEqual(MockKMEHandler.last_enc_slave_id, "user-entered-slave-sae")

            # Verify that server received client's master_sae_id and used it to fetch keys
            self.assertEqual(MockKMEHandler.last_dec_master_id, "client-master-from-config")

            # Verify channel communication over encrypted session
            chan = tc.open_session()
            chan.exec_command("yes")
            chan.close()
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_kex_qkd_full_handshake_with_config_file(self):
        """
        Verify end-to-end handshake when loading configuration from a JSON file.
        """
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))

        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            json.dump({
                "kme_url": self.kme_url,
                "master_sae_id": "file-master-sae",
                "slave_sae_id": "file-target-slave",
                "key_size": 256,
            }, tf)
            cfg_file = tf.name

        try:
            socks = LoopSocket()
            sockc = LoopSocket()
            sockc.link(socks)

            tc = Transport(sockc, qkd_config=cfg_file)
            ts = Transport(socks, qkd_config=cfg_file)

            try:
                for side in (tc, ts):
                    side.get_security_options().kex = ("qkd-etsi014-sha256",)

                ts.add_server_key(host_key)
                event = threading.Event()
                ts.start_server(event, TestServer())

                tc.connect(
                    hostkey=RSAKey(data=host_key.asbytes()),
                    username="slowdive",
                    password="pygmalion",
                )
                event.wait(2.0)

                self.assertTrue(event.is_set())
                self.assertTrue(ts.is_active())
                self.assertTrue(tc.is_authenticated())

                chan = tc.open_session()
                chan.exec_command("yes")
                chan.close()
            finally:
                tc.close()
                ts.close()
                socks.close()
                sockc.close()
        finally:
            os.remove(cfg_file)

    def test_kex_qkd_missing_key_on_server(self):
        """Server fails handshake if KME has no record of the given key_ID."""
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))

        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)

        tc = Transport(sockc, qkd_config=self.config)
        ts = Transport(socks, qkd_config=self.config)

        try:
            for side in (tc, ts):
                side.get_security_options().kex = ("qkd-etsi014-sha256",)

            ts.add_server_key(host_key)
            event = threading.Event()
            ts.start_server(event, TestServer())

            MockKMEHandler.fail_dec_keys = True

            with self.assertRaises(Exception):
                tc.connect(
                    hostkey=RSAKey(data=host_key.asbytes()),
                    username="slowdive",
                    password="pygmalion",
                )
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_kex_qkd_server_challenge_response(self):
        """
        Verify that when server_key_file and server_cert_file are configured,
        the server requests a challenge from KME, signs it with its private key,
        and includes challenge_id, challenge_response, and sae_cert in dec_keys.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate temporary RSA key and self-signed certificate for server
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "server-sae"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )

        with tempfile.NamedTemporaryFile("wb", suffix=".key", delete=False) as kf, \
             tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False) as cf:
            kf.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            cf.write(cert.public_bytes(serialization.Encoding.PEM))
            key_path = kf.name
            cert_path = cf.name

        try:
            server_config = QKDConfig(
                kme_url=self.kme_url,
                master_sae_id="client-sae",
                slave_sae_id="server-sae",
                server_key_file=key_path,
                server_cert_file=cert_path,
            )

            host_key = RSAKey.from_private_key_file(_support("rsa.key"))
            socks = LoopSocket()
            sockc = LoopSocket()
            sockc.link(socks)

            tc = Transport(sockc, qkd_config=self.config)
            ts = Transport(socks, qkd_config=server_config)

            try:
                for side in (tc, ts):
                    side.get_security_options().kex = ("qkd-etsi014-sha256",)

                ts.add_server_key(host_key)
                event = threading.Event()
                ts.start_server(event, TestServer())

                tc.connect(
                    hostkey=RSAKey(data=host_key.asbytes()),
                    username="slowdive",
                    password="pygmalion",
                )
                event.wait(2.0)

                self.assertTrue(event.is_set())
                self.assertTrue(ts.is_active())
                self.assertTrue(tc.is_authenticated())

                # Verify that challenge was requested and parameters sent to dec_keys
                self.assertTrue(MockKMEHandler.challenge_requested)
                self.assertEqual(MockKMEHandler.last_challenge_id, "test-challenge-id-1234")
                self.assertIsNotNone(MockKMEHandler.last_challenge_response)
                self.assertIsNotNone(MockKMEHandler.last_sae_cert)
            finally:
                tc.close()
                ts.close()
                socks.close()
                sockc.close()
        finally:
            os.remove(key_path)
            os.remove(cert_path)
