#!/usr/bin/python3

import argparse
import requests
import json
import urllib3
from urllib.parse import urlparse

# Suppress insecure request warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common function
COMMON_FUNCTIONS = [
    "resend-email", "database-access", "storage-upload", "hyper-function",
    "stripe-webhook", "openai-proxy", "upload-file", "send-email",
    "generate-og-image", "get-user-location", "postgres-api", "restful-service",
    "turnstile-protect", "postgres-integration", "oak-middleware", "discord-bot",
    "telegram-bot", "docs-upload",
]

COMMON_BUCKETS = [
    "test", "public", "uploads", "files", "documents", "images", "avatars",
    "assets", "static", "data", "backup", "backups", "objects", "user-images",
    "assistant-images", "invoices",
]


def make_session(proxy=None):
    session = requests.Session()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def print_curl_example(desc, curl):
    print(f"[cURL] {desc}:\n{curl}\n")


def test_crud_operations(session, rest_url, jwt, tables, token):
    findings = []
    bearer_jwt = token or jwt
    headers = {"apikey": jwt, "Authorization": f"Bearer {bearer_jwt}"}

    for table in tables:
        # READ
        r = session.get(rest_url + table + "?select=*", headers=headers)
        if r.status_code == 200:
            findings.append(f"[!] Able to READ from table '{table}'")
            print_curl_example(
                f"Read from {table}",
                f"curl '{rest_url}{table}?select=*' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'"
            )

        # WRITE
        r_post = session.post(
            rest_url + table,
            headers={**headers, "Content-Type": "application/json", "Prefer": "return=minimal"},
            data=json.dumps({"some_column": "someValue"})
        )
        if r_post.status_code < 300 or r_post.status_code == 400:
            findings.append(f"[!] Attempted WRITE on '{table}', response: {r_post.text}")
            print_curl_example(
                f"Write into {table}",
                f"curl '{rest_url}{table}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' "
                f"-H 'Content-Type: application/json' -H 'Prefer: return=minimal' "
                f"-d '{{\"some_column\": \"someValue\"}}'"
            )

        # UPDATE
        r_patch = session.patch(
            rest_url + table,
            headers={**headers, "Content-Type": "application/json"},
            data=json.dumps({"some_column": "updatedValue"})
        )
        if r_patch.status_code < 300:
            findings.append(f"[!] Able to UPDATE rows in '{table}'")
            print_curl_example(
                f"Update {table}",
                f"curl -X PATCH '{rest_url}{table}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' "
                f"-H 'Content-Type: application/json' -d '{{\"some_column\": \"updatedValue\"}}'"
            )

        # DELETE
        r_delete = session.delete(rest_url + table + "?some_column=eq.someValue", headers=headers)
        if r_delete.status_code < 300 or (r_delete.status_code == 400 and "does not exist" in r_delete.text):
            findings.append(f"[!] Able to DELETE rows in '{table}' (or column leak)")
            print_curl_example(
                f"Delete from {table}",
                f"curl -X DELETE '{rest_url}{table}?some_column=eq.someValue' "
                f"-H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'"
            )

    return findings


def test_stored_procedures(session, rest_url, jwt, discovered_functions, token):
    findings = []
    bearer_jwt = token or jwt
    headers = {
        "apikey": jwt,
        "Authorization": f"Bearer {bearer_jwt}",
        "Content-Type": "application/json",
    }

    for proc in discovered_functions:
        req_url = rest_url + "rpc/" + proc
        req_params = {}

        if proc.startswith("http"):
            req_params = {"content": "string", "content_type": "string", "uri": "string"}

        try:
            r = session.post(req_url, headers=headers, json=req_params, timeout=7)
            if (200 <= r.status_code < 300) or r.status_code == 500:
                findings.append(f"[!] Stored procedure '{proc}' callable with provided JWT.")
                print_curl_example(
                    f"Call stored procedure {proc}",
                    f"curl -X POST '{req_url}' -H 'Content-Type: application/json' "
                    f"-H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -d '{req_params}'"
                )
            elif r.status_code == 401:
                findings.append(f"[-] Stored procedure '{proc}' exists but requires higher privileges (401).")
        except requests.RequestException:
            pass

    return findings


def test_signup(session, auth_url, jwt):
    findings = []
    payload = {"email": "anonymous1337@gmail.com", "password": "SupabaseAudit123!"}

    try:
        r = session.post(auth_url + "signup", json=payload, headers={"apikey": jwt}, timeout=7)
        if r.status_code == 422 and "User already registered" in r.text:
            findings.append("[!] Able to signup new user without restrictions -> anonymous signup enabled.")
        elif r.status_code == 200:
            if "access_token" in r.text:
                findings.append("[!] Able to signup new user without restrictions -> anonymous signup without confirmation enabled.")
            else:
                findings.append("[!] Able to signup new user without restrictions -> anonymous signup enabled.")
            print_curl_example(
                "Signup new user",
                f"curl '{auth_url}signup' -H 'Content-Type: application/json' "
                f"-H 'apikey: {jwt}' -d '{json.dumps(payload)}'"
            )
    except requests.RequestException:
        pass

    return findings


def test_edge_functions(session, func_url, jwt, token):
    findings = []
    bearer_jwt = token or jwt

    for func in COMMON_FUNCTIONS:
        try:
            r = session.post(
                func_url + func,
                headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": jwt},
                json={},
                timeout=7,
            )
            if r.status_code == 401:
                findings.append(f"[!] Edge Function '{func}' exists but provided JWT is insufficient.")
                print_curl_example(
                    f"Edge function {func}",
                    f"curl '{func_url}{func}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -d '{{}}'"
                )
            elif r.status_code != 404:
                findings.append(f"[!] Edge Function '{func}' callable with provided credentials.")
                print_curl_example(
                    f"Edge function {func}",
                    f"curl '{func_url}{func}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -d '{{}}'"
                )
        except requests.RequestException:
            pass

    return findings


def test_storage_ops(session, storage_object_url, discovered_buckets, jwt, token):
    findings = []
    bearer_jwt = token or jwt
    headers = {
        "Authorization": f"Bearer {bearer_jwt}",
        "apikey": jwt,
        "Content-Type": "text/plain",
    }

    for bucket in discovered_buckets:
        try:
            object_path = f"{bucket}/audit_test.txt"
            upload_url = f"{storage_object_url.rstrip('/')}/{object_path}"

            # Step 1: Upload
            r = session.post(upload_url, headers=headers, data=b"hello world", timeout=7)
            try:
                resp_json = r.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r.status_code in (200, 201):
                findings.append(f"[+] Uploaded object in '{object_path}'")
                print(f"Uploaded {object_path}: {r.status_code} -> {resp_json}")
            elif r.status_code == 400 and resp_json.get("statusCode") == "409":
                findings.append(f"[!] Upload conflict (duplicate) in '{object_path}'")
                print(f"Uploaded {object_path}: {r.status_code} -> {resp_json}")
            else:
                print(f"Upload failed ({bucket}): {r.status_code} -> {resp_json}")
                continue

            json_headers = {**headers, "Content-Type": "application/json"}

            # Step 2: Copy
            copy_url = f"{storage_object_url.rstrip('/')}/copy"
            r2 = session.post(
                copy_url,
                headers=json_headers,
                json={"bucketId": bucket, "sourceKey": "audit_test.txt", "destinationKey": "audit_test_copy.txt"},
                timeout=7,
            )
            try:
                resp_json = r2.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r2.status_code == 200:
                findings.append(f"[+] Copied object within '{bucket}'")
                print(f"Copied in {bucket}: {r2.status_code} -> {resp_json}")
            elif r2.status_code == 400 and resp_json.get("statusCode") == "409":
                findings.append(f"[+] Copy conflict (duplicate) within '{bucket}'")
                print(f"Copied in {bucket}: {r2.status_code} -> {resp_json}")
            else:
                print(f"Copy failed ({bucket}): {r2.status_code} -> {resp_json}")

            # Step 3: Move
            move_url = f"{storage_object_url.rstrip('/')}/move"
            r3 = session.post(
                move_url,
                headers=json_headers,
                json={"bucketId": bucket, "sourceKey": "audit_test.txt", "destinationKey": "audit_test_moved.txt"},
                timeout=7,
            )
            try:
                resp_json = r3.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r3.status_code == 200:
                findings.append(f"[+] Moved object within '{bucket}'")
                print(f"Moved in {bucket}: {r3.status_code} -> {resp_json}")
            elif r3.status_code == 400 and resp_json.get("statusCode") == "409":
                findings.append(f"[A] Move conflict (duplicate) within '{bucket}'")
                print(f"Moved in {bucket}: {r3.status_code} -> {resp_json}")
            else:
                print(f"Move failed ({bucket}): {r3.status_code} -> {resp_json}")

            # Step 4: Delete
            r4 = session.delete(upload_url, headers=headers, timeout=7)
            try:
                resp_json = r4.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r4.status_code == 200:
                findings.append(f"[!] Deleted object in '{bucket}'")
                print(f"Deleted in {bucket}: {r4.status_code} -> {resp_json}")

        except requests.RequestException as e:
            print(f"[-] Error with bucket {bucket}: {e}")

    return findings


def discover_open_schema(session, schema_url, jwt, token):
    bearer_jwt = token or jwt
    discovered_tables = []
    discovered_functions = []

    try:
        r = session.get(
            schema_url,
            headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": jwt},
            timeout=7,
        )
    except requests.RequestException:
        return discovered_tables, discovered_functions

    if r.status_code != 200:
        return discovered_tables, discovered_functions

    swagger_json = r.json()
    if swagger_json:
        print_curl_example(
            "Open API Schema found",
            f"curl '{schema_url}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'"
        )
        for path in swagger_json.get("paths", {}):
            if path.startswith("/") and path != "/":
                if path.startswith("/rpc/"):
                    discovered_functions.append(path.replace("/rpc/", ""))
                else:
                    discovered_tables.append(path.lstrip("/"))

    print(discovered_tables, discovered_functions)
    return discovered_tables, discovered_functions


def discover_storage_buckets(session, storage_object_url, bucket_url, jwt, token):
    findings = []
    discovered_buckets = list(COMMON_BUCKETS)
    bearer_jwt = token or jwt
    headers = {"Authorization": f"Bearer {bearer_jwt}", "apikey": jwt}

    try:
        r = session.get(bucket_url, headers=headers, timeout=7)
        if r.status_code == 200:
            try:
                for entry in r.json():
                    bucket_id = entry.get("id")
                    if bucket_id and bucket_id not in discovered_buckets:
                        findings.append(f"[!] Storage bucket '{bucket_id}' accessible.")
                        print_curl_example(
                            f"Access {bucket_id} bucket",
                            f"curl '{bucket_url}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'"
                        )
                        discovered_buckets.append(bucket_id)
            except Exception as e:
                print(f"[-] Failed to parse bucket list: {e}")

        for bucket in discovered_buckets:
            listing_url = storage_object_url + f"list/{bucket}"
            post_body = {"prefix": "%", "limit": 100, "offset": 0, "sortBy": {"column": "name", "order": "asc"}}

            r = session.post(
                listing_url,
                headers={**headers, "Content-Type": "application/json"},
                json=post_body,
                timeout=7,
            )
            if r.status_code == 200 and r.text != "[]":
                findings.append(f"[!] Bucket '{bucket}' items listing available.")
                print_curl_example(
                    f"List items of {bucket}",
                    f"curl -X POST '{listing_url}' -H 'Authorization: Bearer {bearer_jwt}' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"prefix\": \"%\", \"limit\": 100, \"offset\": 0, \"sortBy\": {{\"column\": \"name\", \"order\": \"asc\"}}}}'"
                )

            public_url = storage_object_url + f"public/{bucket}/"
            r = session.get(public_url, timeout=7)
            if r.status_code == 400 and "InvalidKey" in r.text:
                findings.append(f"[!] Bucket '{bucket}' is public but wrong key supplied -> open bucket.")
                print_curl_example(f"Probe public bucket {bucket}", f"curl '{public_url}'")

    except requests.RequestException:
        pass

    return findings, discovered_buckets


def test_supabase(session, url, jwt, token):
    rest_url      = url.rstrip("/") + "/rest/v1/"
    func_url      = url.rstrip("/") + "/functions/v1/"
    auth_url      = url.rstrip("/") + "/auth/v1/"
    storage_url   = url.rstrip("/") + "/storage/v1/object/"
    bucket_url    = url.rstrip("/") + "/storage/v1/bucket/"

    findings = []

    # Auth
    findings.extend(test_signup(session, auth_url, jwt))

    # Schema discovery
    discovered_tables, discovered_functions = discover_open_schema(session, rest_url, jwt, token)

    if discovered_functions:
        print("[!] Found Functions:", discovered_functions)
    if discovered_tables:
        print("[!] Found Tables:", discovered_tables, "\n")
        for table in discovered_tables:
            findings.append(f"[!] Found accessible table via READ: {table}")
            print_curl_example(
                f"Read from {table}",
                f"curl '{rest_url}{table}?select=*' -H 'apikey: {jwt}' -H 'Authorization: Bearer {token or jwt}'"
            )

    # CRUD
    if discovered_tables:
        findings.extend(test_crud_operations(session, rest_url, jwt, discovered_tables, token))

    # Stored procedures
    findings.extend(test_stored_procedures(session, rest_url, jwt, discovered_functions, token))

    # Storage
    new_findings, discovered_buckets = discover_storage_buckets(session, storage_url, bucket_url, jwt, token)
    findings.extend(new_findings)
    findings.extend(test_storage_ops(session, storage_url, discovered_buckets, jwt, token))

    # Edge functions
    findings.extend(test_edge_functions(session, func_url, jwt, token))

    if not findings:
        findings.append("No obvious misconfigurations detected (basic checks).")

    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Supabase instance for common misconfigurations")
    parser.add_argument("url",     help="Supabase project base URL (e.g. https://xyz.supabase.co)")
    parser.add_argument("--jwt",   help="JWT (anon key or service_role) for testing", required=True)
    parser.add_argument("--token", help="Access token from authenticated user", default="")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)", default=None)
    args = parser.parse_args()

    session = make_session(proxy=args.proxy)

    results = test_supabase(session, args.url, args.jwt, args.token)
    for r in results:
        print(r)
