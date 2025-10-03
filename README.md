# SupaProbe - A Supabase probing tool
This tool was written during a deep dive into Supabase - see my [blogpost](https://blog.m1tz.com/sdf)

```
$ python3 supaprobe.py -h
usage: supabase_check.py [-h] --jwt JWT [--token TOKEN] url

Test Supabase instance for common misconfigurations

positional arguments:
  url            Supabase project base URL (e.g. https://xyz.supabase.co)

options:
  -h, --help     show this help message and exit
  --jwt JWT      JWT (anon key or service_role) for testing
  --token TOKEN  accesstoken from user
```

# Results
```
$ python3 supaprobe.py --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im[...]" https://<id>.supabase.co

[!] Found accessible table via READ: accounts
[!] Found accessible table via READ: Account
[!] Found accessible table via READ: Person
[!] Found accessible table via READ: bla
[!] Found accessible table via READ: test
[!] Able to READ from table 'accounts'
[!] Attempted WRITE on 'accounts', response: {"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of 'accounts' in the schema cache"}
[!] Able to DELETE rows in 'accounts' (or column leak)
[!] Able to READ from table 'Account'
[!] Attempted WRITE on 'Account', response: {"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of 'Account' in the schema cache"}
[!] Able to DELETE rows in 'Account' (or column leak)
[!] Able to READ from table 'Person'
[!] Attempted WRITE on 'Person', response: {"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of 'Person' in the schema cache"}
[!] Able to DELETE rows in 'Person' (or column leak)
[!] Able to READ from table 'bla'
[!] Attempted WRITE on 'bla', response: {"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of 'bla' in the schema cache"}
[!] Able to DELETE rows in 'bla' (or column leak)
[!] Able to READ from table 'test'
[!] Attempted WRITE on 'test', response: {"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of 'test' in the schema cache"}
[!] Able to DELETE rows in 'test' (or column leak)
[!] Stored procedure 'test' callable with provided JWT.
[!] Bucket 'test' is public but wrong key supplied -> open bucket.
[!] Able to signup new user without restrictions -> anonymous signup enabled.
[!] Edge Function 'database-access' callable with provided credentials
```
