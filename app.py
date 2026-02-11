import os
from datetime import datetime

import psycopg2
import pytz

# Optional: load .env file if you want local environment support
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from psycopg2.extras import RealDictCursor

load_dotenv()

app = Flask(__name__)
CORS(app)


# ✅ Load DB config from environment variables
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT", "5432"),  # default if not provided
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "dbname": os.getenv("DB_NAME"),
}


def get_db_connection():
    return psycopg2.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        dbname=DB_CONFIG["dbname"],
        cursor_factory=RealDictCursor,
    )


@app.route("/clients", methods=["GET"])
def get_clients():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
    SELECT id,
       client_id,
       name,
       phone_number,
       TO_CHAR(end_date, 'DD-FMMon-YYYY') AS end_date,
       status,
       gender,
       REPLACE(image_url::text, '-', '') AS image_url
    FROM clients
    ORDER BY status;
    """
    )

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows), 200


@app.route("/client/<int:client_id>", methods=["GET"])
def get_client_by_id(client_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
    SELECT id,
       client_id,
       name,
       phone_number,
       TO_CHAR(end_date, 'DD-FMMon-YYYY') AS end_date,
       status,
       gender,
       REPLACE(image_url::text, '-', '') AS image_url
    FROM clients
    WHERE client_id = %s;

    """,
        (client_id,),
    )

    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row is None:
        return jsonify({"error": "Client not found"}), 404

    return jsonify(row), 200


@app.route("/attendance", methods=["GET", "POST"])
def handle_attendance():
    """GET: Retrieve attendance records with optional filters
    POST: Record or update attendance for a client"""

    if request.method == "GET":
        # Get attendance records for a specific date (defaults to today IST)
        record_date = request.args.get("record_date")
        
        # If not provided, use today's IST date
        if not record_date:
            ist = pytz.timezone("Asia/Kolkata")
            now_ist = datetime.now(ist)
            record_date = now_ist.strftime("%Y-%m-%d")

        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT client_id, status FROM attendance WHERE record_date = %s"

        cursor.execute(query, (record_date,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows), 200

    elif request.method == "POST":
        # Record or update attendance with current IST date
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        client_id = data.get("client_id")
        status = data.get("status")

        if not client_id or not status:
            return jsonify({"error": "Missing required fields: client_id, status"}), 400

        if status not in ("Present", "Absent"):
            return jsonify({"error": "Status must be 'Present' or 'Absent'"}), 400

        # Get current date in IST timezone
        ist = pytz.timezone("Asia/Kolkata")
        now_ist = datetime.now(ist)
        record_date = now_ist.strftime("%Y-%m-%d")

        conn = get_db_connection()
        cursor = conn.cursor()

        print(client_id, record_date, status)  # Debugging log

        # Upsert: Insert or update if exists
        cursor.execute(
            """
            INSERT INTO attendance (client_id, record_date, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (client_id, record_date)
            DO UPDATE SET status = EXCLUDED.status
            RETURNING id, client_id, record_date, status;
        """,
            (client_id, record_date, status),
        )

        row = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        # Convert record_date to string for JSON serialization
        if row and row.get("record_date"):
            row["record_date"] = str(row["record_date"])

        return jsonify(row), 201


@app.route("/")
def root():
    return {"message": "Flask API is running!"}, 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
