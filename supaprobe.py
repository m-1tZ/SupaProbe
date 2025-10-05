import argparse
import requests
import base64
import json

# Common function
COMMON_FUNCTIONS = [
    "resend-email",
    "database-access",
    "storage-upload",
    "hyper-function",
    "stripe-webhook",
    "openai-proxy",           # Proxy to OpenAI APIs
    "upload-file",            # Upload handling via Edge Function
    "send-email",             # Email sending via Resend or similar
    "generate-og-image",      # Open Graph image generator
    "get-user-location",      # Retrieves location based on IP
    "postgres-api",           # Basic RESTful CRUD API over tables
    "restful-service",        # REST-style interface for tasks
    "turnstile-protect",      # Cloudflare Turnstile protection
    "postgres-integration",   # Direct Postgres usage
    "oak-middleware",         # Oak routing middleware example
    "discord-bot",            # Slash commands via Discord
    "telegram-bot",           # Telegram bot example
    "docs-upload",            # Working with Supabase Storage
]

# Common bucket names to probe
COMMON_BUCKETS = [
    "test", "public", "uploads", "files", "documents", "images", "avatars", "assets", "static", "data", "backup", "backups", "objects", "user-images", "assistant-images", "invoices"
]

def print_curl_example(desc, curl):
    print(f"[cURL] {desc}:\n{curl}\n")


def test_crud_operations(rest_url, jwt, tables, token):
    findings = []
    bearer_jwt = jwt or token

    headers = {"apikey": jwt, "Authorization": f"Bearer {bearer_jwt}"}
    for table in tables:
        # READ
        r = requests.get(rest_url + table + "?select=*", headers=headers)
        if r.status_code == 200:
            findings.append(f"[!] Able to READ from table '{table}'")
            print_curl_example(f"Read from {table}", f"curl '{rest_url}{table}?select=*' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'")

        # WRITE
        r_post = requests.post(
            rest_url + table,
            headers={**headers, "Content-Type": "application/json", "Prefer": "return=minimal"},
            data=json.dumps({"some_column": "someValue"})
        )
        if r_post.status_code < 300 or r_post.status_code == 400:
            findings.append(f"[!] Attempted WRITE on '{table}', response: {r_post.text}")
            print_curl_example(f"Write into {table}", f"curl '{rest_url}{table}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -H 'Content-Type: application/json' -H 'Prefer: return=minimal' -d '{{ \"some_column\": \"someValue\" }}'")

        # UPDATE
        r_patch = requests.patch(
            rest_url + table,
            headers={**headers, "Content-Type": "application/json"},
            data=json.dumps({"some_column": "updatedValue"})
        )
        if r_patch.status_code < 300:
            findings.append(f"[!] Able to UPDATE rows in '{table}'")
            print_curl_example(f"Update {table}", f"curl -X PATCH '{rest_url}{table}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -H 'Content-Type: application/json' -d '{{ \"some_column\": \"updatedValue\" }}'")

        # DELETE
        r_delete = requests.delete(rest_url + table + "?some_column=eq.someValue", headers=headers)
        if r_delete.status_code < 300 or (r_delete.status_code == 400 and "does not exist" in r_delete.text):
            findings.append(f"[!] Able to DELETE rows in '{table}' (or column leak)")
            print_curl_example(f"Delete from {table}", f"curl -X DELETE '{rest_url}{table}?some_column=eq.someValue' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'")
    return findings

def test_stored_procedures(rest_url, jwt, discovered_functions, token):
    findings = []
    bearer_jwt = jwt or token

    headers = {
        "apikey": jwt,
        "Authorization": f"Bearer {bearer_jwt}",
        "Content-Type": "application/json"
    }
    for proc in discovered_functions:
        req_url = rest_url + "rpc/" + proc
        req_params = {}

        if proc.startswith("http"):
            req_params={"content": "string", "content_type": "string", "uri": "string"}

        try:
            r = requests.post(
                req_url,
                headers=headers,
                json=req_params,
                timeout=7
            )
            # 500er status code means something is not supplied/missing such as parameters
            if (r.status_code >= 200 and r.status_code < 300) or r.status_code == 500:
                findings.append(f"[!] Stored procedure '{proc}' callable with provided JWT.")
                print_curl_example(
                    f"Call stored procedure {proc}",
                    f"curl -X POST '{req_url}' "
                    f"-H 'Content-Type: application/json' -H 'apikey: {jwt}' "
                    f"-H 'Authorization: Bearer {bearer_jwt}' -d '{req_params}'"
                )
            elif r.status_code == 401:
                findings.append(f"[-] Stored procedure '{proc}' exists but requires higher privileges (401).")
        except requests.RequestException:
            pass
    return findings

def test_signup(auth_url, jwt):
    findings = []
    try:
        payload = {"email": "anonymous1337@gmail.com", "password": "SupabaseAudit123!"}
        r = requests.post(auth_url + "signup", json=payload, headers={"apikey": jwt}, timeout=7)
        if r.status_code == 422:
            if "User already registered" in r.text:
                findings.append("[!] Able to signup new user without restrictions -> anonymous signup enabled.")    
        elif r.status_code == 200:            
            if "access_token" in r.text:
                findings.append("[!] Able to signup new user without restrictions -> anonymous signup without confirmation enabled.")
            else:    
                findings.append("[!] Able to signup new user without restrictions -> anonymous signup enabled.")
            print_curl_example("Signup new user", f"curl '{auth_url}signup' -H 'Content-Type: application/json' -H 'apikey: {jwt}' -d '{json.dumps(payload)}'")
    except requests.RequestException:
        pass
    return findings


def test_edge_functions(func_url, jwt, token):
    findings = []
    bearer_jwt=jwt or token

    for func in COMMON_FUNCTIONS:
        try:
            #print(func_url + func)
            r = requests.post(func_url + func, headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": f"{jwt}"}, json={}, timeout=7)
            #print(str(r.status_code))
            if r.status_code == 401:
                findings.append(f"[!] Edge Function '{func}' exist but provided JWT is insufficient.")
                print_curl_example(f"Edge function {func}", f"curl '{func_url}{func}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -d '{{}}'")
            
            elif r.status_code != 404:
                findings.append(f"[!] Edge Function '{func}' callable with provided credentials")
                print_curl_example(f"Edge function {func}", f"curl '{func_url}{func}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}' -H 'apikey: {jwt}' -d '{{}}'")
        except requests.RequestException as e:
            pass
    return findings

import requests

def test_storage_ops(storage_object_url, discovered_buckets, jwt, token):
    findings = []
    bearer_jwt = token or jwt

    for bucket in discovered_buckets:
        try:
            object_path = f"{bucket}/audit_test.txt"
            upload_url = f"{storage_object_url.rstrip('/')}/{object_path}"
            headers = {
                "Authorization": f"Bearer {bearer_jwt}",
                "apikey": jwt,
                "Content-Type": "text/plain",
            }

            # Step 1: Upload file
            data = b"hello world"
            r = requests.post(upload_url, headers=headers, data=data, timeout=7)

            try:
                resp_json = r.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r.status_code in (200, 201):
                findings.append(f"[+] Uploaded object in '{object_path}'")
                print(f"Uploaded {object_path}: {r.status_code} -> {resp_json}")

            elif r.status_code == 400:
                if resp_json.get("statusCode") == '409':
                    findings.append(f"[!] Uploaded object but duplicated in '{object_path}'")
                    print(f"Uploaded {object_path}: {r.status_code} -> {resp_json}")
            else:
                print(f"Upload failed ({bucket}): {r.status_code} -> {resp_json}")
                # No test of copy/move/etc.
                continue

            # Step 2: Copy file
            copy_url = f"{storage_object_url.rstrip('/')}/copy"
            payload_copy = {
                "bucketId": bucket,
                "sourceKey": "audit_test.txt",
                "destinationKey": "audit_test.txt",
            }
            r2 = requests.post(copy_url, headers=headers, json=payload_copy, timeout=7)
            try:
                resp_json = r2.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r2.status_code == 200:
                findings.append(f"[+] Copied object within '{bucket}'")
                print(f"Copied in {bucket}: {r2.status_code} -> {resp_json}")

            elif r2.status_code == 400:
                if resp_json.get("statusCode") == '409':
                    findings.append(f"[+] Copied object but duplicate within '{bucket}'")
                    print(f"Copied in {bucket}: {r2.status_code} -> {resp_json}")

            else:
                print(f"Copy failed ({bucket}): {r2.status_code} -> {resp_json}")

            # Step 3: Move file
            move_url = f"{storage_object_url.rstrip('/')}/move"
            payload_move = {
                "bucketId": bucket,
                "sourceKey": "audit_test.txt",
                "destinationKey": "audit_test.txt",
            }
            r3 = requests.post(move_url, headers=headers, json=payload_move, timeout=7)
            try:
                resp_json = r3.json()
            except ValueError:
                resp_json = {"message": "Invalid JSON response"}

            if r3.status_code == 200:
                findings.append(f"[+] Moved object within '{bucket}'")
                print(f"Moved in {bucket}: {r3.status_code} -> {resp_json}")
            
            elif r3.status_code == 400:
                if resp_json.get("statusCode") == '409':
                    findings.append(f"[A] Moved object but duplicate within '{bucket}'")
                    print(f"Moved in {bucket}: {r3.status_code} -> {resp_json}")

            else:
                print(f"Move failed ({bucket}): {r3.status_code} -> {resp_json}")

            # Step 4: Delete both files
            r4 = requests.delete(upload_url, headers=headers, timeout=7)
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


def discover_open_schema(schema_url, jwt, token):
    bearer_jwt=jwt or token

    response = requests.get(schema_url, headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": f"{jwt}"}, timeout=7)
    if response.status_code != 200:
        return []

    swagger_json = response.json()

    discovered_tables = []
    discovered_functions = []
    
    if swagger_json:
        print_curl_example(f"Open API Schema found", f"curl '{schema_url}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'")

        for path in swagger_json.get("paths", {}):
            if path.startswith("/") and path != "/":
                # RPC - Database functions
                if path.startswith("/rpc/"):
                    discovered_functions.append(path.replace("/rpc/", ""))
                else:    
                    discovered_tables.append(path.replace("/", ""))
    return discovered_tables, discovered_functions


def discover_storage_buckets(storage_object_url, bucket_url, jwt, token):
    findings = []
    discovered_buckets = COMMON_BUCKETS
    bearer_jwt=jwt or token
    
    # Discover buckets and save to discovered_buckets
    try:
        r = requests.get(bucket_url, headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": f"{jwt}"}, timeout=7)
        
        if r.status_code == 200:
            try:
                data = r.json()
                for entry in data:
                    bucket_id = entry.get("id")
                    if bucket_id and bucket_id not in discovered_buckets:
                        findings.append(f"[!] Storage bucket '{bucket_id}' accessible.")
                        print_curl_example(f"Access {bucket_id} bucket", f"curl '{bucket_url}' -H 'apikey: {jwt}' -H 'Authorization: Bearer {bearer_jwt}'")
                        discovered_buckets.append(bucket_id)
            except Exception as e:
                print(f"[-] Failed to parse bucket list: {e}")
        
        for bucket in discovered_buckets:
            post_body = {"prefix": "%", "limit": 100, "offset": 0, "sortBy": { "column": "name", "order": "asc" } }
            listing_url = storage_object_url + f"list/{bucket}"
            
            # Test listing
            r = requests.post(listing_url, headers={"Authorization": f"Bearer {bearer_jwt}", "apikey": f"{jwt}", "Content-Type": "application/json"}, json=post_body,timeout=7)

            if r.status_code == 200 and r.text != "[]":
                findings.append(f"[!] Bucket '{bucket}' items listing available.")
                print_curl_example(f"List items of {bucket}", f"curl -X POST '{listing_url}' -H 'Authorization: Bearer {bearer_jwt}' -H 'Content-Type: application/json' -d '{{\"prefix\": \"%\", \"limit\": 100, \"offset\": 0, \"sortBy\": {{ \"column\": \"name\", \"order\": \"asc\" }} }}'")
            
            # Test whether public
            public_url = storage_object_url+f"public/{bucket}/"
            r = requests.get(public_url, timeout=7)

            if r.status_code == 400 and "InvalidKey" in r.text:
                findings.append(f"[!] Bucket '{bucket}' is public but wrong key supplied -> open bucket.")
                print_curl_example(f"Probe public bucket {bucket}", f"curl '{public_url}'")
    except requests.RequestException:
        pass

    return findings, discovered_buckets

def test_supabase(url, jwt, token):
    rest_url = url.rstrip("/") + "/rest/v1/"
    func_url = url.rstrip("/") + "/functions/v1/"
    auth_url = url.rstrip("/") + "/auth/v1/"
    storage_object_url = url.rstrip("/") + "/storage/v1/object/"
    bucket_url = url.rstrip("/") + "/storage/v1/bucket/"

    findings = []

    # Try READ on common tables
    discovered_tables = []
    discovered_functions = []
    discovered_buckets = []

    bearer_jwt = jwt
    if token != "":
        bearer_jwt = token

    headers = {"apikey": f"{jwt}", "Authorization": f"Bearer {bearer_jwt}"}

    # Signup
    findings.extend(test_signup(auth_url, jwt))

    # Try public schema if exposed and add tables when discovered
    discovered_tables, discovered_functions = discover_open_schema(rest_url, jwt, token)
    print("[!] Found Functions")
    print(discovered_functions)
    print("[!] Found Tables")
    print(discovered_tables)
    print("")
        
    if discovered_tables != []:
        for table in discovered_tables:
            findings.append(f"[!] Found accessible table via READ: {table}")
            print_curl_example(f"Read from {table}", f"curl '{rest_url}{table}?select=*' -H 'apikey: {jwt}' -H f'Authorization: Bearer {bearer_jwt}'")

    # CRUD tests if any tables discovered
    if discovered_tables:
        findings.extend(test_crud_operations(rest_url, jwt, discovered_tables, token))

    # Stored procedures (rpc)
    findings.extend(test_stored_procedures(rest_url, jwt, discovered_functions, token))

    # Storage buckets
    new_findings, discovered_buckets = discover_storage_buckets(storage_object_url, bucket_url, jwt, token)

    if new_findings != []:
        findings.extend(new_findings)

    # Storage upload
    findings.extend(test_storage_ops(storage_object_url, discovered_buckets, jwt, token))

    # Edge functions
    findings.extend(test_edge_functions(func_url, jwt, token))

    if not findings:
        findings.append("No obvious misconfigurations detected (basic checks).")
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Supabase instance for common misconfigurations")
    parser.add_argument("url", help="Supabase project base URL (e.g. https://xyz.supabase.co)")
    parser.add_argument("--jwt", help="JWT (anon key or service_role) for testing", required=True)
    parser.add_argument("--token", help="accesstoken from user", required=False, default="")
    args = parser.parse_args()

    results = test_supabase(args.url, args.jwt, args.token)
    for r in results:
        print(r)
