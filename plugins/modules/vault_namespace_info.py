#!/usr/bin/python
# pylint: disable=E0401
# vault_namespaces_info.py - A custom module plugin for Ansible.
# Author: Your Name (@username)
# License: GPL-3.0-or-later
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    module: vault_namespace_info
    author: Chyna Sanders (@chynasan)
    version_added: "1.2.0"
    short_description: A custom module plugin for Ansible.
    description:
        - Read Vault B(Enterprise) namespaces and related operations using C(/sys/namespaces).
        - Open Source Vault does not expose these APIs; operations will fail with an error from Vault.
        - Uses the collection's shared connection and authentication options; HTTP calls are handled by the namespaces API on the Vault client.
      name:
        description: The name of the namespace to retrieve information for.
        type: str
        required: true
"""

EXAMPLES = """
- name: Return a list of namespaces
  hashicorp.vault.vault_namespace_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"


"""

RETURN = """
message:
  description:
  - A demo message.
  type: str
  returned: always
  sample: "Hello, ansible-creator"
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC

try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
        get_authenticated_client,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import Secrets as VaultSecret
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
        VaultSecretNotFoundError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def main():
    
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(type="str"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    name = module.params.get("name")

    try:
        if name:
            data = client.namespaces.read_namespace(path)
            module.exit_json(
                changed=False,
                namespaces=[{"name": name}],
            )
        else:
            namespace_names = client.namespaces.list_namespaces()
            namespaces = [{"name": namespace_name} for namespace_name in namespace_names]
            module.exit_json(changed=False, namespaces=namespaces)

    except VaultSecretNotFoundError:
        module.exit_json(changed=False, namespaces=[])
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")

if __name__ == "__main__":
    main()