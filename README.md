This is executed with the command:

python sync_policy_groups.py --config config.txt [--readonly]

in which config.txt is a YAML file with the entries:


```
vanity_domain: "<your-vanity-domain>" (used for auth with .zslogin.net - do not include the full domain)
client_id: "<your-oneapi-client-id>"
client_secret: "<your-oneapi-client-secret>"
readonly:True (defaults to False if excluded)
target: <target-microtenant-name>
skiplist:
- "Default"
- <other tenants to not include in source Policy Group sync to target>
```
