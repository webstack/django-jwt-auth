#!/usr/bin/env python
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
# Make sure the app is (at least temporarily) on the import path.
APP_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, APP_DIR)

def run_tests():

    # Making Django run this way is a two-step process. First, call
    # settings.configure() to give Django settings to work with:
    from django.conf import settings

    # Then, call django.setup() to initialize the application registry
    # and other bits:
    import django
    django.setup()

    # Now we instantiate a test runner...
    from django.test.utils import get_runner
    TestRunner = get_runner(settings)

    # And then we run tests and return the results.
    test_runner = TestRunner(verbosity=2, interactive=True)
    failures = test_runner.run_tests(['tests'])
    sys.exit(failures)


if __name__ == '__main__':
    run_tests()
