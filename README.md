This is executed with the command:

python sync_policy_groups.py --config config.txt [--readonly]

in which config.txt is a YAML file with the entries:


```
vanity_domain: "<vanity domain>" (used for auth with .zslogin.net - do not include the full domain)
client_id: "<ZPA API client ID>"
client_secret: "<ZPA API client secret>"
readonly:True
target: <target Microtenant name>
skiplist:
- "Default"
- <other tenants to not include in source Policy Group sync to target>
```
