timelock
========

Create a secret key that can be decrypted in a known amount of time using
parallel-serial hash chains.(1) The creator can compute the timelock in
parallel, taking advantage of the large amount of cheap parallelism available
today, while others are forced to compute it serially, constrained by the lack
of scalar performance growth.
![](https://github.com/nondejus/timelock/blob/master/%E5%9B%97/ArtBoard%20Image%20(500).jpg) 

The chains are constructed such that Bitcoin addresses can be derived from them
and bounties placed, incentivizing third-parties to crack the timelocks. This
gives us a valuable chance to incentivize others to push the envelope of scalar
performance - important knowledge if we are going to have any hope of knowing
how soon our timelocked secrets will actually be revealed! The Bitcoin secret
keys and addresses are constructed from the chains as follows:

    iv -> <chain> -> privkey -> pubkey -> secret -> hashed_secret

    secret        = SHA256(pubkey)
    hashed_secret = RIPEMD160(secret)

Unlocking a given chain starting from the initialization vector gives the
person doing the work the private key, giving them an exclusive opportunity to
collect the bounty. Collecting that bounty forces them to reveal the pubkey,
from which the secret is derived. The hashed_secret is then just a standard
Bitcoin address, letting everyone see how large the bounty is for unlocking the
timelock.

Only a single algorithm - SHA256 - is supported by design: timelock encryption
works best if we're all on an even playing field.


Unlocking a locked timelock
===========================

    ./timelock.py unlock test_timelock.locked

timelock.locked is rewritten in place as the unlocking process progresses. It's
just a JSON file, and contains the secret keys for each address as they are
calculated. You can also add secrets as they are found with the 'addsecret'
command.


Creating a new timelock
=======================

First you want to get an idea of how fast the hashing process is:

    ./timelock.py benchmark

Next create a new timelock. Here we create one with 4 parallel chains that
should take about 1 minute to unlock at 3.0 Mhash/second:

    ./timelock.py create -n 4 1m 3.0 test_timelock

Now for each chain, 0, 1, 2, and 3, compute the final value. Since you have the
initialization vectors for all chains you can compute all chains in parallel:

    ./timelock.py compute test_timelock 0
    ./timelock.py compute test_timelock 1
    ./timelock.py compute test_timelock 2
    ./timelock.py compute test_timelock 3

Each compute command will result in a midstate, and you'll be given a command
to add that midstate to your timelock file:

    ./timelock.py addmidstate test_timelock 0 10000 <hex bytes>

Once all midstates have been added the timelock - now fully unlocked - can be
locked. This removes the initialization vectors from all but the first chain,
forcing it to be unlocked sequentially:

    ./timelock.py lock test_timelock test_timelock.locked


Requirements
============

python3-dev libssl-dev


Build
=====

python3 setup.py build_ext --inplace


Unit Tests
==========

python3 -m unittest discover -s timelock


Bugs
====

Lots of them. For starters files are dangerously re-written in place; they are
not backed up prior to modification.

But hey, v0.1.0 was thrown together in a few hours.


Todo
====

- Automate scanning for revealed secrets and collection of bounties
- Add an easy way to pay to the bounty addresses
- Provide a way for bounty posters to put IV info in blockchain itself w/
  OP_RETURN proved sacrifice to deter fake chains.


Credits
=======

Thanks goes to Amir Taaki for helping develop the initial concept.


References
==========

http://www.gwern.net/Self-decrypting%20files
