#!/usr/bin/env python3
"""
Test script to verify RootDSE query improvements in badsuccessor module
"""

import sys
import os

# Add the NetExec directory to Python path
sys.path.insert(0, '/workspaces/NetExec')

from nxc.modules.badsuccessor import NXCModule
from impacket.ldap import ldapasn1


class MockLDAPConnection:
    """Mock LDAP connection for testing"""
    def __init__(self, base_dn="DC=test,DC=local"):
        self._baseDN = base_dn
    
    def search(self, scope=None, attributes=None, sizeLimit=0, **kwargs):
        """Mock search that simulates successful RootDSE query"""
        if scope and str(scope) == "baseObject":
            # Simulate successful RootDSE response
            result = []
            entry = ldapasn1.SearchResultEntry()
            
            # Create attributes
            attrs = ldapasn1.PartialAttributeList()
            
            if "schemaNamingContext" in attributes:
                schema_attr = ldapasn1.PartialAttribute()
                schema_attr['type'] = ldapasn1.AttributeDescription("schemaNamingContext")
                schema_vals = ldapasn1.Vals()
                schema_vals[0] = ldapasn1.AttributeValue("CN=Schema,CN=Configuration,DC=test,DC=local")
                schema_attr['vals'] = schema_vals
                attrs[0] = schema_attr
                
            if "configurationNamingContext" in attributes:
                config_attr = ldapasn1.PartialAttribute()
                config_attr['type'] = ldapasn1.AttributeDescription("configurationNamingContext")
                config_vals = ldapasn1.Vals()
                config_vals[0] = ldapasn1.AttributeValue("CN=Configuration,DC=test,DC=local")
                config_attr['vals'] = config_vals
                attrs[1] = config_attr
            
            entry['attributes'] = attrs
            result.append(entry)
            return result
        
        return []


class MockConnection:
    """Mock NetExec connection for testing"""
    def __init__(self, base_dn="DC=test,DC=local"):
        self.ldap_connection = MockLDAPConnection(base_dn)


class MockContext:
    """Mock context with logging"""
    class MockLog:
        def debug(self, msg):
            print(f"[DEBUG] {msg}")
        
        def info(self, msg):
            print(f"[INFO] {msg}")
        
        def error(self, msg):
            print(f"[ERROR] {msg}")
    
    def __init__(self):
        self.log = self.MockLog()


def test_rootdse_query():
    """Test the RootDSE query functionality"""
    print("Testing RootDSE query improvements...")
    
    # Create mock objects
    context = MockContext()
    connection = MockConnection()
    
    # Create module instance
    module = NXCModule()
    module.context = context
    
    # Test the get_domain_and_schema_info method
    result = module.get_domain_and_schema_info(connection)
    
    print(f"\nTest Result: {'PASSED' if result else 'FAILED'}")
    print(f"Domain name: {getattr(module, 'domain_name', 'Not set')}")
    print(f"Schema naming context: {getattr(module, 'schema_naming_context', 'Not set')}")
    
    return result


if __name__ == "__main__":
    test_rootdse_query()
