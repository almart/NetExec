#!/usr/bin/env python3
"""
Test script for BadSuccessor module validation
"""
import sys
import os
sys.path.insert(0, '/workspaces/NetExec')

def test_module_import():
    """Test if the module can be imported without errors"""
    try:
        from nxc.modules.badsuccessor import NXCModule
        print("✓ Module import successful")
        return True
    except Exception as e:
        print(f"✗ Module import failed: {e}")
        return False

def test_module_attributes():
    """Test if the module has all required attributes"""
    try:
        from nxc.modules.badsuccessor import NXCModule
        module = NXCModule()
        
        required_attrs = ['name', 'description', 'supported_protocols', 'opsec_safe', 'multiple_hosts']
        missing_attrs = []
        
        for attr in required_attrs:
            if not hasattr(module, attr):
                missing_attrs.append(attr)
        
        if missing_attrs:
            print(f"✗ Missing required attributes: {missing_attrs}")
            return False
        
        # Check attribute values
        print(f"✓ Module name: {module.name}")
        print(f"✓ Module description: {module.description}")
        print(f"✓ Supported protocols: {module.supported_protocols}")
        print(f"✓ OPSEC safe: {module.opsec_safe}")
        print(f"✓ Multiple hosts: {module.multiple_hosts}")
        
        return True
    except Exception as e:
        print(f"✗ Module attribute test failed: {e}")
        return False

def test_module_methods():
    """Test if the module has all required methods"""
    try:
        from nxc.modules.badsuccessor import NXCModule
        module = NXCModule()
        
        required_methods = ['options', 'on_login']
        missing_methods = []
        
        for method in required_methods:
            if not hasattr(module, method) or not callable(getattr(module, method)):
                missing_methods.append(method)
        
        if missing_methods:
            print(f"✗ Missing required methods: {missing_methods}")
            return False
        
        print("✓ All required methods present")
        return True
    except Exception as e:
        print(f"✗ Module method test failed: {e}")
        return False

def test_module_constants():
    """Test if the module has all required constants"""
    try:
        from nxc.modules.badsuccessor import (
            ACCESS_RIGHTS, RELEVANT_RIGHTS, FUNCTIONAL_LEVELS,
            DMSA_OBJECT_GUID, CREATE_CHILD_ACE_RIGHT
        )
        print("✓ All required constants imported successfully")
        print(f"  - ACCESS_RIGHTS: {len(ACCESS_RIGHTS)} entries")
        print(f"  - RELEVANT_RIGHTS: {len(RELEVANT_RIGHTS)} entries")
        print(f"  - FUNCTIONAL_LEVELS: {len(FUNCTIONAL_LEVELS)} entries")
        print(f"  - DMSA_OBJECT_GUID: {DMSA_OBJECT_GUID}")
        return True
    except Exception as e:
        print(f"✗ Module constants test failed: {e}")
        return False

def main():
    print("BadSuccessor Module Validation Test")
    print("=" * 40)
    
    tests = [
        test_module_import,
        test_module_attributes,
        test_module_methods,
        test_module_constants
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        print(f"\nRunning {test.__name__}...")
        if test():
            passed += 1
        print("-" * 40)
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The BadSuccessor module is ready for use.")
        return 0
    else:
        print("❌ Some tests failed. Please check the module implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
