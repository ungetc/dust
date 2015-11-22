# Stuff used by multiple makefiles.

# This is an abomination, but it works: $^ is only present
# in gmake, and $> is only present in BSD make, so whichever
# we're running under, this expands to "all the dependencies."
# Ick ick ick get it off me get it off me.
ALLDEPS=$^ $>

