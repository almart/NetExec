#!/usr/bin/env python3
"""
Standalone test script for the badsuccessor module to verify it works correctly.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_module_import():
    """Test that the module can be imported without errors."""
    try:
        from nxc.modules.badsuccessor import NXCModule
        print("✅ Module import: SUCCESS")
        return NXCModule
    except Exception as e:
        print(f"❌ Module import: FAILED - {e}")
        return None

def test_module_instantiation(module_class):
    """Test that the module can be instantiated."""
    try:
        module = module_class()
        print("✅ Module instantiation: SUCCESS")
        return module
    except Exception as e:
        print(f"❌ Module instantiation: FAILED - {e}")
        return None

def test_module_attributes(module):
    """Test that the module has required attributes."""
    required_attrs = ['name', 'description', 'supported_protocols', 'multiple_hosts']
    
    for attr in required_attrs:
        if hasattr(module, attr):
            value = getattr(module, attr)
            print(f"✅ Attribute {attr}: {value}")
        else:
            print(f"❌ Attribute {attr}: MISSING")
            return False
    
    return True

def test_module_methods(module):
    """Test that the module has required methods."""
    required_methods = ['options', 'on_login']
    
    for method in required_methods:
        if hasattr(module, method) and callable(getattr(module, method)):
            print(f"✅ Method {method}: EXISTS")
        else:
            print(f"❌ Method {method}: MISSING")
            return False
    
    return True

def test_options_method(module):
    """Test that the options method works correctly."""
    try:
        # Create mock objects for testing
        class MockContext:
            def __init__(self):
                self.log = MockLogger()
        
        class MockLogger:
            def info(self, msg): pass
            def error(self, msg): pass
            def warn(self, msg): pass
            def debug(self, msg): pass
        
        class MockConnection:
            pass
        
        class MockArgs:
            pass
        
        result = module.options(MockContext(), {})
        
        if result is None:
            print("✅ Options method: SUCCESS (returns None as expected)")
            return True
        else:
            print(f"⚠️ Options method: Returns {result} instead of None")
            return False
            
    except Exception as e:
        print(f"❌ Options method: ERROR - {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("Running badsuccessor module tests...\n")
    
    # Test 1: Import
    module_class = test_module_import()
    if not module_class:
        return False
    
    # Test 2: Instantiation
    module = test_module_instantiation(module_class)
    if not module:
        return False
    
    # Test 3: Attributes
    if not test_module_attributes(module):
        return False
    
    # Test 4: Methods
    if not test_module_methods(module):
        return False
    
    # Test 5: Options method
    if not test_options_method(module):
        return False
    
    print("\n🎉 All tests passed! The badsuccessor module appears to be working correctly.")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
