# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of Timelock.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of Timelock, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest

import timelock.kernel

# Add testcases for every algorithm and kernel to the module
for algorithm in timelock.kernel.ALGORITHMS:
    class testcase_class(unittest.TestCase):
        pass
    testcase_class.__doc__ = "Algorithm '%s'" % algorithm.SHORT_NAME

    for kernel in algorithm.KERNELS:
        def kernel_test(self):
            for (nonce, n, expected) in algorithm.TEST_VECTORS:
                actual = kernel.run(nonce, n)
                if actual != expected:
                    self.fail('test vector (%r, %d) -> %r failed; got %r instead' % (
                        nonce, n, expected,
                        actual))
        kernel_test.__doc__ = "Kernel '%s'" % kernel.SHORT_NAME
        #import pdb; pdb.set_trace()
        setattr(testcase_class, 'test_kernel_%s' % kernel.SHORT_NAME, kernel_test)

    testcase_class.__name__ = 'Test_Algorithm_%s' % algorithm.SHORT_NAME
    globals()[testcase_class.__name__] = testcase_class
    del testcase_class
