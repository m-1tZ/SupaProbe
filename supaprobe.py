#!/usr/bin/python3

import argparse
import re
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
    "telegram-bot", "docs-upload", "vehicle-lookup"
]

# Used as seed list for both storage bucket guessing and table name brute-forcing.
# Bucket names are typically hyphenated slugs; table names are typically snake_case —
# both forms are kept so the list works for either purpose without transformation.
COMMON_BUCKETS_TABLES = [
    # --- storage-style slugs (hyphens) ---
    "user-images", "assistant-images",
    # --- generic storage / file buckets ---
    "uploads", "files", "documents", "images", "avatars", "assets", "static",
    "objects", "backup", "backups", "public",
    # --- common DB table names (snake_case / lowercase) ---
    "users", "user", "accounts", "account", "profiles", "profile",
    "sessions", "tokens", "keys", "secrets", "credentials",
    "roles", "permissions", "policies",
    "orgs", "organizations", "teams", "members", "memberships",
    "workspaces", "projects", "tasks", "todos", "issues",
    "posts", "comments", "likes", "reactions", "tags", "categories",
    "messages", "notifications", "events", "logs", "audit_logs",
    "orders", "invoices", "payments", "subscriptions", "plans", "products",
    "customers", "contacts", "leads", "companies",
    "emails", "email_templates",
    "settings", "config", "features", "flags",
    "data", "test", "dev", "staging",
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


def _pascal_to_snake(name: str) -> str:
    """Convert PascalCase to snake_case."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().strip("_")


def discover_open_schema(session, rest_url, graphql_url, jwt, token):
    bearer_jwt = token or jwt

    discovered_tables = set()
    discovered_functions = set()

    headers = {
        "Authorization": f"Bearer {bearer_jwt}",
        "apikey": jwt,
        "Content-Type": "application/json",
    }

    # -----------------------
    # 1. Try REST (OpenAPI)
    # -----------------------
    try:
        r = session.get(rest_url, headers=headers, timeout=7)

        if r.status_code == 200:
            swagger_json = r.json()

            print_curl_example(
                "OpenAPI schema (REST)",
                f"curl '{rest_url}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'"
            )

            for path in swagger_json.get("paths", {}):
                if path.startswith("/rpc/"):
                    discovered_functions.add(path.replace("/rpc/", ""))
                elif path.startswith("/") and path != "/":
                    discovered_tables.add(path.lstrip("/"))

        else:
            print(f"[-] REST schema access blocked ({r.status_code}) → trying GraphQL")

    except requests.RequestException:
        print("[-] REST schema request failed → trying GraphQL")

    # -----------------------
    # 2. GraphQL (pg_graphql)
    # -----------------------
    # Strategy: query queryType.fields — in pg_graphql every exposed table/view
    # appears here as a "<TableName>Collection" field (return type ends in
    # "Connection").  Plain scalar fields are RPC/stored-procedure proxies.
    # mutationType.fields give us a second signal: insertInto/update/deleteFrom
    # prefixes reveal tables even when reads are locked down by RLS.
    gql_query = {
        "query": """
        {
          __schema {
            queryType {
              fields {
                name
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
            mutationType {
              fields {
                name
              }
            }
          }
        }
        """
    }

    try:
        r = session.post(graphql_url, headers=headers, json=gql_query, timeout=7)

        if r.status_code == 200 and "data" in r.text:
            data = r.json()

            print_curl_example(
                "GraphQL schema introspection",
                f"curl -X POST '{graphql_url}' -H 'apikey: {jwt}' "
                f"-H 'Authorization: Bearer {bearer_jwt}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{json.dumps(gql_query)}'"
            )

            schema = data.get("data", {}).get("__schema", {})

            # --- queryType: tables vs RPC functions ---
            # pg_graphql exposes tables as fields whose return type name ends in
            # "Connection" (e.g. UsersCollection → UsersConnection).
            query_fields = schema.get("queryType", {}).get("fields") or []
            for field in query_fields:
                name      = field.get("name", "")
                type_info = field.get("type", {})
                type_name = type_info.get("name") or ""
                of_name   = (type_info.get("ofType") or {}).get("name") or ""

                connection_name = type_name if type_name.endswith("Connection") \
                                  else of_name if of_name.endswith("Connection") \
                                  else None

                if connection_name:
                    # Strip "Connection" suffix, convert PascalCase → snake_case
                    raw   = connection_name[: -len("Connection")]
                    snake = _pascal_to_snake(raw)
                    if snake:
                        discovered_tables.add(snake)
                        print(f"[GraphQL] Table (queryType): {snake}")
                elif name not in ("node",):
                    # Non-Connection, non-noise → likely an RPC proxy
                    discovered_functions.add(name)
                    print(f"[GraphQL] Function (queryType): {name}")

            # --- mutationType: secondary table signal ---
            # Mutation names follow: insertInto<Table>Collection,
            # update<Table>Collection, deleteFrom<Table>Collection
            mutation_fields = schema.get("mutationType", {}).get("fields") or []
            for field in mutation_fields:
                name = field.get("name", "")
                for prefix in ("insertInto", "update", "deleteFrom"):
                    if name.startswith(prefix):
                        raw   = name[len(prefix):].replace("Collection", "")
                        snake = _pascal_to_snake(raw)
                        if snake and snake not in discovered_tables:
                            discovered_tables.add(snake)
                            print(f"[GraphQL] Table (mutationType/{prefix}): {snake}")
                        break

        else:
            print(f"[-] GraphQL introspection failed ({r.status_code})")

    except requests.RequestException:
        print("[-] GraphQL request failed")

    return list(discovered_tables), list(discovered_functions)


def discover_storage_buckets(session, storage_object_url, bucket_url, jwt, token, seed_list=None):
    findings = []
    discovered_buckets = list(seed_list) if seed_list is not None else list(COMMON_BUCKETS_TABLES)
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

    graphql_url = url.rstrip("/") + "/graphql/v1"
    rest_url      = url.rstrip("/") + "/rest/v1/"
    func_url      = url.rstrip("/") + "/functions/v1/"
    auth_url      = url.rstrip("/") + "/auth/v1/"
    storage_url   = url.rstrip("/") + "/storage/v1/object/"
    bucket_url    = url.rstrip("/") + "/storage/v1/bucket/"

    findings = []

    # Auth
    findings.extend(test_signup(session, auth_url, jwt))

    # Schema discovery
    discovered_tables, discovered_functions = discover_open_schema(session, rest_url, graphql_url, jwt, token)

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

    # Merge discovered tables into the common seed list so storage probing and
    # CRUD both benefit from schema-derived names without duplicates.
    combined_tables = list(COMMON_BUCKETS_TABLES)
    for t in discovered_tables:
        if t not in combined_tables:
            combined_tables.append(t)

    # CRUD — run against the full combined list
    findings.extend(test_crud_operations(session, rest_url, jwt, combined_tables, token))

    # Stored procedures
    findings.extend(test_stored_procedures(session, rest_url, jwt, discovered_functions, token))

    # Storage — pass combined list so discovered table names are also probed as bucket names
    new_findings, discovered_buckets = discover_storage_buckets(session, storage_url, bucket_url, jwt, token, combined_tables)
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
