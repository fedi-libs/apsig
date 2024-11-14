import sys
from unittest import TestLoader
from unittest import TextTestRunner

if __name__ == '__main__':
    loader = TestLoader()
    test = loader.discover("tests")
    runner = TextTestRunner()
    runner.run(test)
