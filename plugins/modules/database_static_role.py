# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


DOCUMENTATION = """
    module: database_static_role
    author: Hannah DeFazio (@hdefazio)
    version_added: "1.2.0"
    short_description: Manage database static roles in HashiCorp Vault.
    description:
      - This module allows you to create, update, and delete database static roles in HashiCorp Vault.
      - Static roles provide a mechanism to use Vault as a credential broker for existing database accounts.
      - Use C(state=present) to create or update a static role.
      - Use C(state=absent) to delete a static role.
    options:
      name:
        description: The name of the database static role.
        type: str
        required: true
      state:
        description:
          - Goal state for the database static role.
          - Use V(present) to create or update the static role.
          - Use V(absent) to delete the static role.
        choices: [present, absent]
        default: present
        type: str
      db_name:
        description:
          - The name of the database connection to use for this static role.
          - This references a connection created by the M(hashicorp.vault.database_connection) module.
          - Required when O(state=present).
        type: str
      username:
        description:
          - The database username that Vault will manage and rotate credentials for.
          - This must be an existing user in the database.
          - Required when O(state=present).
        type: str
"""

EXAMPLES = """
- name: Create a database static role
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-postgres-db
    username: vault-user
    rotation_period: 86400

- name: Create a database static role with custom rotation statements
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-mysql-db
    username: app_user
    rotation_period: 3600
    rotation_statements:
      - "ALTER USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';"
    database_mount_path: database
"""

RETURN = """
msg:
  description: A message describing the result of the operation.
  returned: always
  type: str
  sample: "Static role 'my-static-role' created successfully"
raw:
  description: The configuration settings for the database static role created/updated.
  returned: when I(state=present)
  type: dict
  sample:
    {
        "db_name": "my-postgres-db",
        "username": "vault-user",
        "rotation_period": 86400,
        "rotation_statements": []
    }
"""


__metaclass__ = type  # pylint: disable=C0103

import copy

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultDatabaseStaticRoles,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def ensure_present(module: AnsibleModule, client: VaultClient, db_static_roles: VaultDatabaseStaticRoles) -> None:
    """Create or update a database static role."""
    name = module.params.get("name")

    # Build configuration from module parameters, filtering out None values
    config_params = (
        "username",
        "db_name"
    )
    config = {key: val for key in config_params if (val := module.params.get(key)) is not None}

    # Check if the static role already exists
    # VaultSecretNotFoundError is raised if the role doesn't exist
    try:
        existing = db_static_roles.read_static_role(name)
    except VaultSecretNotFoundError:
        existing = {}

    # If role exists and no changes needed, exit early with changed=False
    needs_update = any(existing.get(k) != v for k, v in config.items())
    if existing and not needs_update:
        module.exit_json(
            changed=False,
            msg="The database static role already exists with the same data.",
            raw=existing
        )

    operation = "updated" if existing else "created"

    # In check mode, report what would happen without making changes
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have {operation} database static role '{name}' if not in check mode",
            raw=existing
        )

    # Actually create or update the static role
    db_static_roles.create_or_update_static_role(name, config)

    # Read back the configuration to return to the user
    result = db_static_roles.read_static_role(name)

    module.exit_json(
        changed=True,
        msg=f"Database static role {name!r} {operation} successfully",
        raw=result
    )

    


def main() -> None:
    """Entry point for module execution"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default="present", choices=["present", "absent"]),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            db_name=dict(),
            username=dict(),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ["db_name", "username"]),),
        supports_check_mode=True
    )

    client = get_authenticated_client(module)

    mount_path = module.params["database_mount_path"]
    db_static_roles = VaultDatabaseStaticRoles(client, mount_path=mount_path)

    state = module.params["state"]
    try:
        if state == "present":                                                                                                                
            ensure_present(module, client, db_static_roles)  
                                                                                      
    except VaultSecretNotFoundError as e:
        module.exit_json(data={})
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
