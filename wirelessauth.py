import os
import time
import json
import pymysql
import traceback
import secrets
import string
import subprocess
import hashlib
from datetime import datetime
from flask import Flask, request, redirect, render_template, abort, jsonify, g
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config

class WirelessAuth:
    def __init__(self):
        self.app = Flask("wirelessauth")
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_host=1)
        self.app.url_map.strict_slashes = False

    #
    # routing
    #
    def routes(self):
        @self.app.before_request
        def before_request_handler():
            g.db = pymysql.connect(
                host=config['db-host'],
                user=config['db-user'],
                password=config['db-pass'],
                database=config['db-name'],
                autocommit=True
            )

        @self.app.context_processor
        def inject_recurring_data():
            return {
                'now': datetime.utcnow(),
            }

        # routing
        @self.app.route('/')
        def index():
            allowed = request.remote_addr.startswith("10.241")
            return render_template("index.html", allowed=allowed)

        @self.app.route('/invite/<hash>', methods=['GET'])
        def invited(hash):
            query = "SELECT COUNT(id) FROM invites WHERE id = %s"
            cursor = g.db.cursor()
            cursor.execute(query, (hash))
            rows = cursor.fetchone()

            # token not found
            if rows[0] == 0:
                abort(404)

            return render_template("create.html", id=hash)

        @self.app.route('/create/<hash>', methods=['POST'])
        def create(hash):
            query = "SELECT COUNT(id) FROM invites WHERE id = %s"
            cursor = g.db.cursor()
            cursor.execute(query, (hash))
            rows = cursor.fetchone()

            # token not found
            if rows[0] == 0:
                abort(404)

            username = request.form['username'].lower()

            alphabet = string.ascii_letters + string.digits
            password = ''.join(secrets.choice(alphabet) for i in range(16))

            command = f"smbencrypt {password} 2>&1 | tail -1 | awk '{{ print $2 }}'"
            encrypt = subprocess.run(command, shell=True, capture_output=True)
            hashed = encrypt.stdout.decode('utf-8').strip()

            query = """
                INSERT INTO radcheck (username, attribute, op, value)
                VALUES (%s, 'NT-Password', ':=', %s)
            """
            cursor.execute(query, (username, hashed))

            # remove invite
            query = "DELETE FROM invites WHERE id = %s"
            cursor.execute(query, (hash))

            return render_template("created.html", username=username, password=password)

        @self.app.route('/invite')
        def invite():
            if not request.remote_addr.startswith("10.241"):
                abort(401)

            now = time.time()
            value = f"wireless-invite-{now}"
            hash = hashlib.md5(value.encode("utf-8"))
            id = hash.hexdigest()

            cursor = g.db.cursor()
            query = "INSERT INTO invites (id) VALUES (%s)"
            cursor.execute(query, (id))

            return render_template("invite.html", id=id)

    def serve(self):
        print("[+] listening")
        self.app.run(host="10.241.0.254", port=8874, debug=True, threaded=True)


if __name__ == "__main__":
    wireless = WirelessAuth()
    wireless.routes()
    wireless.serve()
