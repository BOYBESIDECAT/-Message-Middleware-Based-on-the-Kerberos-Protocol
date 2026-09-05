#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TGS server for Kerberos phase-2 (ignore CA verification)."""

import json
import os
import secrets
import signal
import socket
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from kerberos_core import (
    MSG_TGS_REQUEST,
    MSG_TGS_RESPONSE,
    DEFAULT_LIFETIME4,
    DEFAULT_SKEW_SECONDS,
    AsyncLogger,
    build_packet,
    canonical_json,
    des_decrypt,
    des_encrypt,
    error_packet,
    load_key_ref,
    load_kv_config,
    parse_utc,
    read_packet,
    send_all,
    utc_now_str,
)


DEFAULT_CFG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8001,
    "tgs_db_path": "data/tgs.db",
    "tgs_id": "TGS-001",
    "service_id": "CHATSERVER-001",
    "ktgs_ref": "ktgs_default",
    "keys_path": "data/keys.json",
    "log_path": "logs/tgs.log.txt",
    "time_skew_seconds": DEFAULT_SKEW_SECONDS,
    "lifetime4_seconds": DEFAULT_LIFETIME4,
    "max_workers": 32,
}


def ensure_keys(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ktgs_default": "0011223344556677", "kv_chat_default": "8899aabbccddeeff"}, f, ensure_ascii=False, indent=2)


def ensure_tgs_db(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS service_registry (
            service_id TEXT PRIMARY KEY,
            kv_ref TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'enabled'
        )
        """
    )
    cur.execute("INSERT OR IGNORE INTO service_registry(service_id, kv_ref, status) VALUES(?,?,?)", ("CHATSERVER-001", "kv_chat_default", "enabled"))
    conn.commit()
    conn.close()


class TGSServer:
    def __init__(self, config_path: str = "tgs_server.conf"):
        self.cfg = load_kv_config(config_path, DEFAULT_CFG)
        ensure_keys(self.cfg["keys_path"])
        ensure_tgs_db(self.cfg["tgs_db_path"])
        self.ktgs = load_key_ref(self.cfg["keys_path"], self.cfg["ktgs_ref"])
        self.log = AsyncLogger(self.cfg["log_path"])
        self.stop_evt = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=int(self.cfg["max_workers"]))
        self.sock = None

    def _query_service(self, service_id: str):
        conn = sqlite3.connect(self.cfg["tgs_db_path"])
        cur = conn.cursor()
        cur.execute("SELECT kv_ref, status FROM service_registry WHERE service_id=?", (service_id,))
        row = cur.fetchone()
        conn.close()
        return row

    def _validate_time(self, ts: str):
        now = parse_utc(utc_now_str())
        t = parse_utc(ts)
        return abs((now - t).total_seconds()) <= int(self.cfg["time_skew_seconds"])

    def _validate_ticket_lifetime(self, ts2: str, lifetime2: int):
        now = parse_utc(utc_now_str())
        issue = parse_utc(ts2)
        return (now - issue).total_seconds() <= lifetime2

    def _decrypt_ticket_tgs(self, ticket_hex: str):
        plain = des_decrypt(self.ktgs, bytes.fromhex(ticket_hex)).decode("utf-8")
        return json.loads(plain)

    def _decrypt_authenticator(self, auth_hex: str, kc_tgs: bytes):
        plain = des_decrypt(kc_tgs, bytes.fromhex(auth_hex)).decode("utf-8")
        return json.loads(plain)

    def _build_tgs_response(self, service_id: str, kv: bytes, ticket_tgs_obj: dict):
        kc_v = secrets.token_bytes(8)
        ts4 = utc_now_str()
        lifetime4 = int(self.cfg["lifetime4_seconds"])

        ticket_v_plain = {
            "Kc_v": kc_v.hex(),
            "IDc": ticket_tgs_obj["IDc"],
            "ADc": ticket_tgs_obj["ADc"],
            "IDv": service_id,
            "TS4": ts4,
            "Lifetime4": lifetime4,
        }
        ticket_v = des_encrypt(kv, canonical_json(ticket_v_plain).encode("utf-8")).hex()

        response_plain = {
            "Kc_v": kc_v.hex(),
            "IDv": service_id,
            "TS4": ts4,
            "Lifetime4": lifetime4,
            "Ticket_v": ticket_v,
        }
        kc_tgs = bytes.fromhex(ticket_tgs_obj["Kc_tgs"])
        cipher_hex = des_encrypt(kc_tgs, canonical_json(response_plain).encode("utf-8")).hex()
        payload = {"data": {"cipher_hex": cipher_hex}}
        return build_packet(MSG_TGS_RESPONSE, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def _handle_tgs_request(self, payload: dict):
        data = payload.get("data", {})
        idv = data.get("IDv", "")
        ticket_tgs_hex = data.get("Ticket_tgs", "")
        auth_hex = data.get("Authenticator_c", "")
        if not idv or not ticket_tgs_hex or not auth_hex:
            return error_packet("TGS_REQUEST_FORMAT_ERROR", "missing IDv/Ticket_tgs/Authenticator_c")

        try:
            ticket = self._decrypt_ticket_tgs(ticket_tgs_hex)
        except Exception:
            return error_packet("TGT_DECRYPT_ERROR", "cannot decrypt Ticket_tgs")

        if ticket.get("IDtgs") != self.cfg["tgs_id"]:
            return error_packet("TGS_ID_MISMATCH", "ticket not for this tgs")
        if not self._validate_ticket_lifetime(ticket.get("TS2", "1970-01-01T00:00:00Z"), int(ticket.get("Lifetime2", 0))):
            return error_packet("TGT_EXPIRED", "Ticket_tgs expired")

        try:
            kc_tgs = bytes.fromhex(ticket.get("Kc_tgs", ""))
            auth = self._decrypt_authenticator(auth_hex, kc_tgs)
        except Exception:
            return error_packet("AUTH_DECRYPT_ERROR", "cannot decrypt Authenticator_c")

        if auth.get("IDc") != ticket.get("IDc") or auth.get("ADc") != ticket.get("ADc"):
            return error_packet("TGS_AUTH_MISMATCH", "IDc/ADc not match")
        if not self._validate_time(auth.get("TS3", "1970-01-01T00:00:00Z")):
            return error_packet("AUTH_TIME_SKEW", "TS3 out of window")

        row = self._query_service(idv)
        if not row:
            return error_packet("KEY_CONFIG_ERROR", "service not registered")
        kv_ref, status = row
        if status != "enabled":
            return error_packet("SERVICE_DISABLED", f"service status={status}")

        try:
            kv = load_key_ref(self.cfg["keys_path"], kv_ref)
            return self._build_tgs_response(idv, kv, ticket)
        except KeyError:
            return error_packet("KEY_CONFIG_ERROR", "kv_ref missing")
        except Exception as e:
            self.log.log("ERROR", "TGS", f"build TGS_RESPONSE failed: {e}", MSG_TGS_REQUEST, "SERVER_INTERNAL_ERROR")
            return error_packet("SERVER_INTERNAL_ERROR", "build TGS_RESPONSE failed")

    def _handle_conn(self, conn: socket.socket, addr):
        peer = f"{addr[0]}:{addr[1]}"
        self.log.log("INFO", "TGS", f"connection from {peer}")
        try:
            while not self.stop_evt.is_set():
                msg_type, payload = read_packet(conn)
                if msg_type != MSG_TGS_REQUEST:
                    send_all(conn, error_packet("INVALID_MSG_TYPE", f"expect 0x03 got 0x{msg_type:02X}"))
                    break
                resp = self._handle_tgs_request(payload)
                send_all(conn, resp)
        except Exception as e:
            self.log.log("WARN", "TGS", f"peer {peer} disconnected: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve_forever(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.cfg["listen_host"], int(self.cfg["listen_port"])))
        self.sock.listen(128)
        self.log.log("INFO", "TGS", f"TGS listening on {self.cfg['listen_host']}:{self.cfg['listen_port']}")
        while not self.stop_evt.is_set():
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            self.pool.submit(self._handle_conn, conn, addr)

    def close(self):
        self.stop_evt.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.log.close()


def main():
    server = TGSServer("tgs_server.conf")

    def _stop(_sig=None, _frm=None):
        server.close()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        server.serve_forever()
    finally:
        server.close()


if __name__ == "__main__":
    main()
