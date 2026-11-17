This is executed with the command:

python sync_policy_groups.py --config config.txt

in which config.txt is a YAML file with the entries:


```
vanity_domain: "<vanity domain.zslogin.net>"
client_id: "<ZPA API client ID>"
client_secret: "<ZPA API client secret>"
target: <target Microtenant name>
skiplist:
- "Default"
- <other tenants to not include in source Policy Group sync to target>
```
