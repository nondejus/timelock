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

def xor_bytes(a, b):
    """Bytewise XOR"""
    if len(a) != len(b):
        raise ValueError('a and b must be same length')

    return bytes([a[i] ^ b[i] for i in range(len(a))])

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

    def __init__(self, n, iv=None, encrypted_iv=None, algorithm=timelock.kernel.AlgorithmSHA256):
        """Create a new timelock chain"""

        self.n = n
        self.algorithm = algorithm
        self.iv = iv
        self.encrypted_iv = encrypted_iv

        self.i = 0
        self.midstate = self.iv

    @staticmethod
    def midstate_to_seckey(midstate):
        return bitcoin.wallet.CBitcoinSecret.from_secret_bytes(midstate)

    @staticmethod
    def seckey_to_secret(seckey):
        return hashlib.sha256(seckey.pub).digest()

    @staticmethod
    def secret_to_hashed_secret(secret):
        return hashlib.new('ripemd160', secret).digest()

    def encrypt_iv(self, prev_secret):
        if self.iv is None:
            raise ValueError('Decrypted IV not available')
        self.encrypted_iv = xor_bytes(self.iv, prev_secret)

    def decrypt_iv(self, prev_secret):
        if self.encrypted_iv is None:
            raise ValueError('Encrypted IV not available')
        self.iv = xor_bytes(self.encrypted_iv, prev_secret)
        self.midstate = self.iv
        self.i = 0

    def add_secret(self, secret):
        """Update chain with newly discovered secret

        Returns True on success, False otherwise
        """
        if self.hashed_secret is None:
            raise ValueError("Can't add secret if chain not yet computed!")

        if self.hashed_secret == self.secret_to_hashed_secret(secret):
            self.secret = secret
            return True

        else:
            return False

    def add_pubkey_secret(self, pubkey_secret):
        """Add newly discovered pubkey secret to chain"""
        secret = hashlib.sha256(pubkey_secret).digest()
        return self.add_secret(secret)

    def add_seckey(self, seckey):
        """Add newly discovered seckey secret to chain

        Returns True on succese, False otherwise
        """
        return self.add_pubkey_secret(seckey.pub)


    def unlock(self, t, j = None):
        """Unlock the timelock for up to t seconds

        j - Optionally stop the computation at a specific index

        Returns True if the timelock is now unlocked, False otherwise.
        """
        if self.i == 0:
            self.midstate = self.iv

        if self.midstate is None:
            import pdb; pdb.set_trace()
            raise ValueError("Can't unlock chain: midstate not available")

        start_time = time.clock()

        if j is None:
            j = self.n

        if j > self.n:
            raise ValueError('j > self.n')

        max_m = 1
        while self.i < j and time.clock() - start_time < t:
            t0 = time.clock()

            m = min(j - self.i, max_m)
            # FIXME: need some kind of "fastest kernel" thing here
            self.midstate = self.algorithm.KERNELS[-1].run(self.midstate, m)
            self.i += m

            if time.clock() - t0 < 0.025:
                max_m *= 2

        assert self.i <= self.n

        if self.i == self.n:
            # Done! Create the secret key, secret, and finally hashed
            # secret.
            self.seckey = self.midstate_to_seckey(self.midstate)
            self.secret = self.seckey_to_secret(self.seckey)
            self.hashed_secret = self.secret_to_hashed_secret(self.secret)

        return self.secret is not None




class Timelock:
    num_chains = None
    chains = None

    @property
    def secret(self):
        if len(self.chains) < self.num_chains:
            return None
        return self.chains[-1].secret

    def __init__(self, num_chains, n, algorithm=timelock.kernel.AlgorithmSHA256, ivs=None):
        """Create a new timelock

        num_chains - # of chains
        n          - # of hashes for each chain
        """

        self.algorithm = algorithm
        self.num_chains = num_chains
        self.n = n

        if ivs is None:
            ivs = [os.urandom(self.algorithm.NONCE_LENGTH) for i in range(num_chains)]
        self.chains = [TimelockChain(self.n, iv=ivs[i], algorithm=algorithm) for i in range(num_chains)]

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

        json_chains = []
        for known_chain in self.chains:
            json_known_chain = {}


            assert(known_chain.algorithm == self.algorithm)
            assert(known_chain.n == self.n)

            json_known_chain['iv'] = nb2x(known_chain.iv)
            json_known_chain['encrypted_iv'] = nb2x(known_chain.encrypted_iv)

            json_known_chain['n'] = known_chain.n
            json_known_chain['i'] = known_chain.i
            json_known_chain['midstate'] = nb2x(known_chain.midstate)

            json_known_chain['hashed_secret'] = None
            if known_chain.hashed_secret is not None:
                json_known_chain['hashed_secret'] = str(bitcoin.wallet.CBitcoinAddress.from_bytes(known_chain.hashed_secret, 0))

            json_known_chain['seckey'] = str(known_chain.seckey) if known_chain.seckey is not None else None
            json_known_chain['secret'] = nb2x(known_chain.secret)

            json_chains.append(json_known_chain)

        r['chains'] = json_chains

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

        self.chains = []
        for json_known_chain in obj['chains']:
            known_chain = TimelockChain(self.n,
                                iv=nx(json_known_chain['iv']),
                                encrypted_iv=nx(json_known_chain['encrypted_iv']),
                                algorithm=self.algorithm)

            known_chain.i = json_known_chain['i']
            known_chain.midstate = nx(json_known_chain['midstate'])

            known_chain.hashed_secret = json_known_chain['hashed_secret']
            if known_chain.hashed_secret is not None:
                known_chain.hashed_secret = bitcoin.wallet.CBitcoinAddress(known_chain.hashed_secret)

            known_chain.secret = nx(json_known_chain['secret'])

            known_chain.seckey = json_known_chain['seckey']
            if known_chain.seckey is not None:
                known_chain.seckey = bitcoin.wallet.CBitcoinSecret(known_chain.seckey)

            self.chains.append(known_chain)

        return self

    def make_locked(self):
        """Create a locked timelock from a fully computed timelock

        Returns a new timelock
        """

        if len(self.chains) < self.num_chains:
            # FIXME: there's gotta be a better way to explain this...
            raise ValueError('Timelock is already locked!')

        # Make sure every chain is fully computed
        for (i, chain) in enumerate(self.chains):
            if not chain.unlock(0):
                raise ValueError("Chain %d is still locked" % i)

            if 0 < i:
                # Encrypt IV with previous secret
                chain.encrypt_iv(self.chains[i-1].secret)

        locked = self.__class__.__new__(self.__class__)

        locked.algorithm = self.algorithm
        locked.num_chains = self.num_chains
        locked.n = self.n
        locked.chains = []

        for unlocked_chain in self.chains:
            locked_chain = TimelockChain(self.n,
                    iv=None, encrypted_iv=unlocked_chain.encrypted_iv,
                    algorithm=self.algorithm)
            locked_chain.hashed_secret = unlocked_chain.hashed_secret
            locked.chains.append(locked_chain)

        locked.chains[0].iv = self.chains[0].iv

        return locked

    def add_secret(self, secret):
        """Add newly discovered secret

        All chains will be attempted.

        Returns True on success, False on failure
        """
        for known_chain in self.chains:
            if known_chain.hashed_secret is None:
                raise ValueError("Can't add secret if chain not yet computed!")

            if known_chain.add_secret(secret):
                return True
            if known_chain.add_pubkey_secret(secret):
                return True
            if hasattr(secret, 'pub') and known_chain.add_seckey_secret(secret):
                return True

        return False


    def unlock(self, t):
        """Unlock the timelock for up to t seconds

        Returns True if the timelock is now unlocked, False if otherwise
        """
        start_time = time.clock()

        while self.secret is None and time.clock() - start_time < t:
            for (i, chain) in enumerate(self.chains):
                if chain.secret is not None:
                    continue

                if chain.iv is None:
                    assert(i > 0)

                    # Decrypt iv with previous chain's secret
                    chain.decrypt_iv(self.chains[i-1].secret)

                if chain.unlock(t):
                    # return early
                    t = -1

                break

        return self.secret is not None
