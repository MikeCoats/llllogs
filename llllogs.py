#!/usr/bin/env python
"""Liberated, Light-weight, Leak-proof Logs.

Parses a set of log files and saves them to a structured database.

User identifiable information is hashed and saved to sub-tables that can be
`DROP`ped to pseudonomise the data. The hashed columns in the main table could be
`UPDATE`d to an auto-incrementing index to anonymise the data, or erased completely
to remove all user behaviour from the data.

This program is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this
program. If not, see <https://www.gnu.org/licenses/>.
"""

__copyright__ = "Copyright (C) 2024  Mike Coats"
__license__ = "GPL-3.0-or-later"
__contact__ = "i.am@mikecoats.com"

__author__ = "Mike Coats"
__credits__ = ["Mike Coats"]

__maintainer__ = "Mike Coats"
__email__ = "i.am@mikecoats.com"

__status__ = "Production"
__version__ = "1.1.0"


import hashlib
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime

import apachelogs


@dataclass
class Server:
    """The server portion of the log lines.
    This allows us to hold the logs for several servers."""

    vhost: str
    port: int


@dataclass
class User:
    """The user portion of the log lines.

    Hashing the user fields in the main table allows for a level of privacy and
    psuedonomisation.
    """

    remote: str
    referer: str
    agent: str

    @property
    def hashed_remote(self):
        """Get a SHA3-224 hashed copy of the visitor's IP."""
        return hashlib.sha3_224(self.remote.encode("utf-8")).hexdigest()

    @property
    def hashed_referer(self):
        """Get a SHA3-224 hashed copy of the visitor's last page."""
        return hashlib.sha3_224(self.referer.encode("utf-8")).hexdigest()

    @property
    def hashed_agent(self):
        """Get a SHA3-224 hashed copy of the visitor's browser."""
        return hashlib.sha3_224(self.agent.encode("utf-8")).hexdigest()


@dataclass
class Request:
    """The main portion of the log lines."""

    time: datetime
    method: str
    path: str
    params: str
    http: str
    status: int
    bytes: int


@dataclass
class LogLine:
    """The complete line from a log file."""

    server: Server
    user: User
    request: Request


def create_tables(con: sqlite3.Connection) -> None:
    """Create all of the tables in the SQLite DB if they don't already exist."""
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS remote (hash PRIMARY KEY, value)")
    cur.execute("CREATE TABLE IF NOT EXISTS referer (hash PRIMARY KEY, value)")
    cur.execute("CREATE TABLE IF NOT EXISTS agent (hash PRIMARY KEY, value)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS log (
            vhost,
            port,
            remote REFERENCES remote (hash),
            time,
            method,
            path,
            params,
            http,
            status,
            bytes,
            referer REFERENCES referer (hash),
            agent REFERENCES agent (hash),
            UNIQUE (
                vhost,
                port,
                remote,
                time,
                method,
                path,
                params,
                http,
                status,
                bytes,
                referer,
                agent
            )
        )
        """
    )
    con.commit()


def write_log_line(con: sqlite3.Connection, log_line: LogLine) -> None:
    """Write a single log line to the DB."""
    cur = con.cursor()

    cur.execute(
        "INSERT OR IGNORE INTO remote (hash,value) VALUES (?,?)",
        (log_line.user.hashed_remote, log_line.user.remote),
    )
    cur.execute(
        "INSERT OR IGNORE INTO referer (hash,value) VALUES (?,?)",
        (log_line.user.hashed_referer, log_line.user.referer),
    )
    cur.execute(
        "INSERT OR IGNORE INTO agent (hash,value) VALUES (?,?)",
        (log_line.user.hashed_agent, log_line.user.agent),
    )
    cur.execute(
        """
        INSERT OR IGNORE INTO log (
            vhost,
            port,
            remote,
            time,
            method,
            path,
            params,
            http,
            status,
            bytes,
            referer,
            agent
        ) VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?
        )
        """,
        (
            log_line.server.vhost,
            log_line.server.port,
            log_line.user.hashed_remote,
            log_line.request.time,
            log_line.request.method,
            log_line.request.path,
            log_line.request.params,
            log_line.request.http,
            log_line.request.status,
            log_line.request.bytes,
            log_line.user.hashed_referer,
            log_line.user.hashed_agent,
        ),
    )


def main():
    """Parse a set of log files and save them in to a structured database."""
    con = sqlite3.connect("logs.db")
    create_tables(con)
    parser = apachelogs.LogParser(apachelogs.VHOST_COMBINED)

    input_files = sys.argv[1:]
    for input_file in input_files:
        print("Reading " + input_file + "...")
        with open(input_file, "r", encoding="utf-8") as f:
            contents = f.readlines()
            entries = parser.parse_lines(contents)

            for e in entries:
                request = e.request_line
                request_parts = request.split(" ")
                url = request_parts[1]
                url_parts = url.split("?")

                write_log_line(
                    con,
                    LogLine(
                        Server(vhost=e.virtual_host, port=e.server_port),
                        User(
                            remote=e.remote_host,
                            referer=e.headers_in["Referer"] or "",
                            agent=e.headers_in["User-agent"] or "",
                        ),
                        Request(
                            time=e.request_time,
                            method=request_parts[0],
                            path=url_parts[0],
                            params=url_parts[1] if len(url_parts) > 1 else "",
                            http=request_parts[2],
                            status=e.final_status,
                            bytes=e.bytes_out,
                        ),
                    ),
                )
        con.commit()


if __name__ == "__main__":
    main()
