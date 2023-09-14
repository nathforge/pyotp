import sys

# Use secrets module if available (Python version >= 3.6) per PEP 506
if sys.version_info >= (3, 6):
    from secrets import SystemRandom
else:
    from random import SystemRandom

random = SystemRandom()
