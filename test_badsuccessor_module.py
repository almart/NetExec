#!/usr/bin/env python3
"""
Test script to validate the badsuccessor NetExec module functionality.
"""

import sys
import os
sys.path.insert(0, '/workspaces/NetExec')

def test_module_import():
    """Test that the module can be imported without errors."""
    try:
        from nxc.modules.badsuccessor import NXCModule
        print("✓ Module imports successfully")
        return True
    except Exception as e:
        print(f"✗ Module import failed: {e}")
        return False

def test_module_options():
    """Test that the module options are properly defined."""
    try:
        from nxc.modules.badsuccessor import NXCModule
        
        # Create a module instance
        module = NXCModule()
        
        # Check required attributes
        assert hasattr(module, 'name'), "Module missing 'name' attribute"
        assert hasattr(module, 'description'), "Module missing 'description' attribute"
        assert hasattr(module, 'supported_protocols'), "Module missing 'supported_protocols' attribute"
        assert hasattr(module, 'opsec_safe'), "Module missing 'opsec_safe' attribute"
        assert hasattr(module, 'multiple_hosts'), "Module missing 'multiple_hosts' attribute"
        assert hasattr(module, 'options'), "Module missing 'options' attribute"
        
        # Test that options method is callable
        assert callable(module.options), "options attribute is not callable"
        
        # Check basic attributes
        assert module.name == "badsuccessor", f"Expected name 'badsuccessor', got '{module.name}'"
        assert "ldap" in module.supported_protocols, "Module should support ldap protocol"
        
        print("✓ Module options properly defined")
        print(f"  - Name: {module.name}")
        print(f"  - Protocols: {module.supported_protocols}")
        return True
    except Exception as e:
        print(f"✗ Module options test failed: {e}")
        return False

def test_module_methods():
    """Test that required methods exist."""
    try:
        from nxc.modules.badsuccessor import NXCModule
        
        module = NXCModule()
        
        # Check for required methods (based on actual NetExec module structure)
        required_methods = ['options', 'on_login', 'find_writable_ou_for_dmsa', 
                          'create_dmsa_object', 'perform_badsuccessor_attack', 'cleanup_dmsa',
                          'check_windows_2025_schema', 'get_user_dn']
        
        for method in required_methods:
            assert hasattr(module, method), f"Missing method: {method}"
            assert callable(getattr(module, method)), f"Method {method} is not callable"
        
        print("✓ All required methods exist and are callable")
        print(f"  - Methods: {required_methods}")
        return True
    except Exception as e:
        print(f"✗ Module methods test failed: {e}")
        return False

def test_action_parsing():
    """Test action parameter validation."""
    try:
        from nxc.modules.badsuccessor import NXCModule
        
        module = NXCModule()
        
        # Test default action after initialization
        assert module.action == 'check', f"Default action should be 'check', got '{module.action}'"
        
        # Test options method can be called
        class MockContext:
            class log:
                @staticmethod
                def error(msg): pass
        
        mock_context = MockContext()
        
        # Test with empty options
        module.options(mock_context, {})
        assert module.action == 'check', "Default action should remain 'check'"
        
        # Test with action option
        module.options(mock_context, {"ACTION": "attack"})
        assert module.action == 'attack', "Action should be set to 'attack'"
        
        print("✓ Action parsing works correctly")
        print(f"  - Default action: check")
        print(f"  - Can set action: attack")
        return True
    except Exception as e:
        print(f"✗ Action parsing test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing NetExec badsuccessor module...\n")
    
    tests = [
        test_module_import,
        test_module_options,
        test_module_methods,
        test_action_parsing
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
        print()
    
    print(f"Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! The badsuccessor module is ready for use.")
        print("\nExample usage:")
        print("# Check for vulnerability")
        print("nxc ldap <target> -u <username> -p <password> -M badsuccessor")
        print("nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=check")
        print()
        print("# Perform attack")
        print("nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=attack TARGET_USER=Administrator")
        print()
        print("# Cleanup")
        print("nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=cleanup DMSA_FULL_DN='CN=evil_dmsa,OU=...'")
        
        return True
    else:
        print("❌ Some tests failed. Please fix the issues before using the module.")
        return False

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
