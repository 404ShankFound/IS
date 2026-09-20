"""Local record storage for the HealthSecure lab program."""

import os
import pickle


RECORD_FILE = os.path.join(os.path.dirname(__file__), "healthsecure_records.pkl")


def load_records():
    if not os.path.exists(RECORD_FILE):
        return []

    try:
        with open(RECORD_FILE, "rb") as file:
            return pickle.load(file)
    except (OSError, pickle.UnpicklingError, EOFError):
        return []


def save_records(records):
    with open(RECORD_FILE, "wb") as file:
        pickle.dump(records, file)


def add_record(record):
    records = load_records()
    records.append(record)
    save_records(records)


def get_record(record_id):
    for record in load_records():
        if record["record_id"] == record_id:
            return record
    return None


def record_exists(record_id):
    return get_record(record_id) is not None
