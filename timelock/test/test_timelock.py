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

import timelock

class Test_TimelockChain(unittest.TestCase):
    def test(self):
        """Chain creation and unlocking"""
        chain = timelock.TimelockChain(3, iv=b'\x00'*32)

        self.assertEqual(chain.secret, None)
        self.assertEqual(chain.hashed_secret, None)
        self.assertEqual(chain.i, 0)


        # do one hash
        self.assertFalse(chain.unlock(1, j=1))
        self.assertEqual(chain.i, 1)
        self.assertEqual(chain.midstate, b'fhz\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d\r_)%')
        self.assertEqual(chain.secret, None)
        self.assertEqual(chain.hashed_secret, None)

        # complete
        self.assertTrue(chain.unlock(1))
        self.assertEqual(chain.i, 3)
        self.assertEqual(chain.midstate, b'\x12w\x13U\xe4l\xd4|q\xed\x17!\xfdS\x19\xb3\x83\xcc\xa3\xa1\xf9\xfc\xe3\xaa\x1c\x8c\xd3\xbd7\xaf \xd7')
        self.assertEqual(chain.secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')
        self.assertEqual(chain.hashed_secret, b'\xf0\xf3n\xad\xe0\xb9\xfdS\xe8DX\x0c\x93\xb5\xddg\xe1\xa1|\xad')

        # further unlocking does nothing
        self.assertTrue(chain.unlock(1))
        self.assertEqual(chain.i, 3)
        self.assertEqual(chain.midstate, b'\x12w\x13U\xe4l\xd4|q\xed\x17!\xfdS\x19\xb3\x83\xcc\xa3\xa1\xf9\xfc\xe3\xaa\x1c\x8c\xd3\xbd7\xaf \xd7')
        self.assertEqual(chain.secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')
        self.assertEqual(chain.hashed_secret, b'\xf0\xf3n\xad\xe0\xb9\xfdS\xe8DX\x0c\x93\xb5\xddg\xe1\xa1|\xad')


class Test_Timelock(unittest.TestCase):
    def test(self):
        """Timelock creation and unlocking"""

        # A single chain
        tl = timelock.Timelock(1, 3, ivs=[b'\x00'*32])
        self.assertEqual(tl.secret, None)

        self.assertTrue(tl.unlock(1))

        # Unlocked now
        self.assertEqual(tl.secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')

        # Further computations do nothing
        self.assertTrue(tl.unlock(1))
        self.assertEqual(tl.secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')


        # Two chains
        tl = timelock.Timelock(2, 3, ivs=[b'\x00'*32]*2)
        self.assertEqual(tl.secret, None)

        # Unlock first chain
        self.assertFalse(tl.unlock(1, from_first_chain=True))
        self.assertEqual(tl.secret, None)
        self.assertEqual(tl.chains[0].secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')

        # Unlock second chain
        self.assertTrue(tl.unlock(1, from_first_chain=True))
        self.assertEqual(tl.secret, b'\xe55\xda\x89|\xf9r\xdb\xacx\x99\x9d&\xbc\xbc \xf0\xbchNr\xff\xa0AUE8\xabb\x13\x8b\x04')


        # Make a locked Timelock from our fully computed one
        tl2 = tl.make_locked()
        self.assertEqual(tl2.secret, None)
        self.assertEqual(len(tl2.chains), 2)

        self.assertFalse(tl2.unlock(1))
        self.assertTrue(tl2.unlock(1))
        self.assertEqual(tl2.secret, tl.secret)
