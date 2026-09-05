#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AS server for Kerberos phase-1 (ignore CA verification)."""

import json
import os
import secrets
import signal
import socket
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from kerberos_core import (
    MSG_AS_REQUEST,
    MSG_AS_RESPONSE,
    DEFAULT_LIFETIME2,
    DEFAULT_SKEW_SECONDS,
    AsyncLogger,
    build_packet,
    canonical_json,
    des_encrypt,
    error_packet,
    hash64,
    load_key_ref,
    load_kv_config,
    parse_utc,
    read_packet,
    send_all,
    utc_now_str,
)


DEFAULT_CFG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8000,
    "as_db_path": "data/as.db",
    "tgs_id": "TGS-001",
    "ktgs_ref": "ktgs_default",
    "keys_path": "data/keys.json",
    "as_machine_id": "AS-HOST-001",
    "identity_store_path": "secure/as_identity",
    "log_path": "logs/as.log.txt",
    "time_skew_seconds": DEFAULT_SKEW_SECONDS,
    "lifetime2_seconds": DEFAULT_LIFETIME2,
    "max_workers": 32,
}


def ensure_as_db(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_account (
            user_id TEXT PRIMARY KEY,
            kc_hex TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'normal'
        )
        """
    )
    alice_kc = hash64("test123").hex()
    cur.execute("INSERT OR IGNORE INTO user_account(user_id, kc_hex, status) VALUES(?,?,?)", ("Alice", alice_kc, "normal"))
    conn.commit()
    conn.close()


def ensure_keys(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ktgs_default": "0011223344556677", "kv_chat_default": "8899aabbccddeeff"}, f, ensure_ascii=False, indent=2)


class ASServer:
    def __init__(self, config_path: str = "as_server.conf"):
        self.cfg = load_kv_config(config_path, DEFAULT_CFG)
        ensure_keys(self.cfg["keys_path"])
        ensure_as_db(self.cfg["as_db_path"])
        self.ktgs = load_key_ref(self.cfg["keys_path"], self.cfg["ktgs_ref"])
        self.log = AsyncLogger(self.cfg["log_path"])
        self.stop_evt = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=int(self.cfg["max_workers"]))
        self.sock = None

    def _query_user_kc(self, user_id: str):
        conn = sqlite3.connect(self.cfg["as_db_path"])
        cur = conn.cursor()
        cur.execute("SELECT kc_hex, status FROM user_account WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        conn.close()
        return row

    def _validate_ts1(self, ts1: str):
        now = parse_utc(utc_now_str())
        ts = parse_utc(ts1)
        return abs((now - ts).total_seconds()) <= int(self.cfg["time_skew_seconds"])

    def _build_as_response(self, kc: bytes, idc: str, adc: str):
        kc_tgs = secrets.token_bytes(8)
        ts2 = utc_now_str()
        lifetime2 = int(self.cfg["lifetime2_seconds"])

        ticket_tgs_plain = {
            "Kc_tgs": kc_tgs.hex(),
            "IDc": idc,
            "ADc": adc,
            "IDtgs": self.cfg["tgs_id"],
            "TS2": ts2,
            "Lifetime2": lifetime2,
        }
        ticket_tgs = des_encrypt(self.ktgs, canonical_json(ticket_tgs_plain).encode("utf-8")).hex()

        response_plain = {
            "Kc_tgs": kc_tgs.hex(),
            "IDtgs": self.cfg["tgs_id"],
            "TS2": ts2,
            "Lifetime2": lifetime2,
            "Ticket_tgs": ticket_tgs,
        }
        cipher_hex = des_encrypt(kc, canonical_json(response_plain).encode("utf-8")).hex()
        payload = {"data": {"cipher_hex": cipher_hex}}
        return build_packet(MSG_AS_RESPONSE, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def _handle_as_request(self, payload: dict):
        data = payload.get("data", {})
        idc = data.get("IDc", "")
        idtgs = data.get("IDtgs", "")
        ts1 = data.get("TS1", "")
        adc = data.get("ADc", "127.0.0.1")

        if not idc or not idtgs or not ts1:
            return error_packet("AS_REQUEST_FORMAT_ERROR", "missing IDc/IDtgs/TS1")
        if idtgs != self.cfg["tgs_id"]:
            return error_packet("K_TGS_CONFIG_ERROR", "IDtgs mismatch")
        if not self._validate_ts1(ts1):
            return error_packet("AUTH_TIME_SKEW", "TS1 out of window")

        row = self._query_user_kc(idc)
        if not row:
            return error_packet("USER_NOT_FOUND", "user not exists")
        kc_hex, status = row
        if status != "normal":
            return error_packet("USER_STATUS_INVALID", f"status={status}")

        try:
            kc = bytes.fromhex(kc_hex)
            if len(kc) != 8:
                return error_packet("USER_KC_INVALID", "kc length invalid")
            return self._build_as_response(kc, idc, adc)
        except Exception as e:
            self.log.log("ERROR", "AS", f"build response failed: {e}", MSG_AS_REQUEST, "SERVER_INTERNAL_ERROR")
            return error_packet("SERVER_INTERNAL_ERROR", "build AS_RESPONSE failed")

    def _handle_conn(self, conn: socket.socket, addr):
        peer = f"{addr[0]}:{addr[1]}"
        self.log.log("INFO", "AS", f"connection from {peer}")
        try:
            while not self.stop_evt.is_set():
                msg_type, payload = read_packet(conn)
                if msg_type != MSG_AS_REQUEST:
                    send_all(conn, error_packet("INVALID_MSG_TYPE", f"expect 0x01 got 0x{msg_type:02X}"))
                    break
                resp = self._handle_as_request(payload)
                send_all(conn, resp)
        except Exception as e:
            self.log.log("WARN", "AS", f"peer {peer} disconnected: {e}")
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
        self.log.log("INFO", "AS", f"AS listening on {self.cfg['listen_host']}:{self.cfg['listen_port']}")

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
    server = ASServer("as_server.conf")

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
