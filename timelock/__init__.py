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

import bitcoin.core
import bitcoin.wallet
import hashlib
import os
import time

import timelock.kernel

class TimelockChain:
    # Hash algorithm
    algorithm = None

    # initialization vector
    iv = None

    # total # of hashes
    n = None

    seckey = None
    secret = None

    # hash of the secret
    hashed_secret = None

    # current step # and state of the chain computation
    i = None
    midstate = None

    def __init__(self, n, iv=None, algorithm=timelock.kernel.AlgorithmSHA256):
        """Create a new timelock chain"""

        self.n = n
        self.algorithm = algorithm
        if not iv:
            iv = os.urandom(self.algorithm.NONCE_LENGTH)
        self.iv = iv

        self.i = 0
        self.midstate = self.iv

    def unlock(self, t, j = None):
        """Unlock the timelock for up to t seconds

        j - Optionally stop the computation at a specific index

        Returns True if the timelock is now unlocked, False otherwise.
        """
        start_time = time.clock()

        if j is None:
            j = self.n

        max_m = 1
        while self.i < j and time.clock() - start_time < t:
            t0 = time.clock()

            m = min(j - self.i, max_m)
            # FIXME: need some kind of "fastest kernel" thing here
            self.midstate = self.algorithm.KERNELS[-1].run(self.midstate, m)
            self.i += m

            if self.i == self.n:
                # Done! Create the secret key, secret, and finally hashed
                # secret.
                self.seckey = bitcoin.wallet.CBitcoinSecret.from_secret_bytes(self.midstate)
                self.secret = hashlib.sha256(self.seckey.pub).digest()
                self.hashed_secret = hashlib.new('ripemd160', self.secret).digest()
                break

            if time.clock() - t0 < 0.025:
                max_m *= 2

        assert self.i <= self.n

        return self.secret is not None


def xor_bytes(a, b):
    """Bytewise XOR"""
    if len(a) != len(b):
        raise ValueError('a and b must be same length')

    return bytes([a[i] ^ b[i] for i in range(len(a))])


class Timelock:
    num_chains = None
    known_chains = None
    encrypted_ivs = None

    @property
    def secret(self):
        if len(self.known_chains) < self.num_chains:
            return None
        return self.known_chains[-1].secret

    def __init__(self, num_chains, n, algorithm=timelock.kernel.AlgorithmSHA256, ivs=None):
        """Create a new timelock

        num_chains - # of chains
        n          - # of hashes for each chain
        """

        self.algorithm = algorithm
        self.num_chains = num_chains
        self.n = n

        if ivs is None:
            ivs = [None for i in range(num_chains)]
        self.known_chains = [TimelockChain(self.n, iv=ivs[i], algorithm=algorithm) for i in range(num_chains)]
        self.encrypted_ivs = [None for i in range(num_chains-1)]

    def to_json(self):
        """Convert to JSON-compatible primitives"""

        def nb2x(b):
            if b is None:
                return b
            else:
                return bitcoin.core.b2x(b)

        r = {}
        r['algorithm'] = self.algorithm.SHORT_NAME
        r['num_chains'] = self.num_chains
        r['n'] = self.n
        r['encrypted_ivs'] = [nb2x(iv) for iv in self.encrypted_ivs]

        json_known_chains = []
        for known_chain in self.known_chains:
            json_known_chain = {}


            assert(known_chain.algorithm == self.algorithm)
            assert(known_chain.n == self.n)

            json_known_chain['iv'] = nb2x(known_chain.iv)

            json_known_chain['n'] = known_chain.n
            json_known_chain['midstate'] = nb2x(known_chain.midstate)

            json_known_chain['hashed_secret'] = None
            if known_chain.hashed_secret is not None:
                json_known_chain['hashed_secret'] = str(bitcoin.wallet.CBitcoinAddress.from_bytes(known_chain.hashed_secret, 0))

            json_known_chain['seckey'] = str(known_chain.seckey) if known_chain.seckey is not None else None
            json_known_chain['secret'] = nb2x(known_chain.secret)

            json_known_chains.append(json_known_chain)

        r['known_chains'] = json_known_chains

        return r


    @classmethod
    def from_json(cls, obj):
        """Convert from JSON-compatible primitives"""
        self = cls.__new__(cls)

        def nx(x):
            if x is None:
                return None
            else:
                return bitcoin.core.x(x)

        self.algorithm = timelock.kernel.ALGORITHMS_BY_NAME[obj['algorithm']]
        self.num_chains = obj['num_chains']
        self.n = obj['n']
        self.encrypted_ivs = [nx(iv) for iv in obj['encrypted_ivs']]

        self.known_chains = []
        for json_known_chain in obj['known_chains']:
            known_chain = TimelockChain(self.n,
                                iv=nx(json_known_chain['iv']),
                                algorithm=self.algorithm)

            known_chain.midstate = nx(json_known_chain['midstate'])

            known_chain.hashed_secret = json_known_chain['hashed_secret']
            if known_chain.hashed_secret is not None:
                known_chain.hashed_secret = bitcoin.wallet.CBitcoinAddress(known_chain.hashed_secret)

            known_chain.secret = nx(json_known_chain['secret'])

            known_chain.seckey = json_known_chain['seckey']
            if known_chain.seckey is not None:
                known_chain.seckey = bitcoin.wallet.CBitcoinSecret(known_chain.seckey)

            self.known_chains.append(known_chain)

        return self

    def compute(self, i, t):
        """Compute the timelock for up to t seconds

        i - index of the chain to compute

        Returns True if the specified chain is complete, False otherwise
        """
        if not (0 <= i < self.num_chains):
            raise ValueError('i out of bounds')

        if self.known_chains[i].unlock(t):
            if i < self.num_chains-1:
                # Encrypt IV for next chain
                self.encrypted_ivs[i] = xor_bytes(self.known_chains[i].secret, self.known_chains[i+1].iv)

        return self.known_chains[i].secret is not None

    def make_locked(self):
        """Create a locked timelock from a fully computed timelock

        Returns a new timelock
        """
        if None in self.encrypted_ivs:
            raise ValueError("Can't make locked timelock; current timelock not fully computed")

        locked = self.__class__.__new__(self.__class__)

        locked.algorithm = self.algorithm
        locked.num_chains = self.num_chains
        locked.n = self.n
        locked.known_chains = [TimelockChain(self.n, iv=self.known_chains[0].iv, algorithm=self.algorithm)]
        locked.encrypted_ivs = self.encrypted_ivs

        return locked


    def unlock(self, t):
        """Unlock the timelock for up to t seconds

        Returns True if the timelock is now unlocked, False if otherwise
        """
        start_time = time.clock()

        while self.secret is None and time.clock() - start_time < t:
            if self.known_chains[-1].unlock(t):
                # return early
                t = -1

                if len(self.known_chains) < self.num_chains:
                    iv = xor_bytes(self.encrypted_ivs[len(self.known_chains)-1], self.known_chains[-1].secret)

                    next_chain = TimelockChain(self.n, iv, self.algorithm)
                    self.known_chains.append(next_chain)

                else:
                    # This was the last chain; we're done!
                    pass

        return self.secret is not None
