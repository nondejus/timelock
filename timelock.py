#!/usr/bin/env python3

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


import sys

if sys.version_info.major != 3:
    raise ImportError("Python3 required")

import argparse
import logging

import timelock.kernel

# Commands

def cmd_benchmark(args):
    algo = timelock.kernel.AlgorithmSHA256

    kernels = []
    if args.kernel:
        for kernel_name in args.kernel:
            try:
                kernels.append(algo.KERNELS_BY_NAME[kernel_name])
            except KeyError:
                logging.error("Unknown kernel '%s'" % kernel_name)
                sys.exit(1)
    else:
        kernels = timelock.kernel.AlgorithmSHA256.KERNELS


    run_results = {}
    for kernel in kernels:
        logging.info("Benchmarking kernel '%s'" % kernel.SHORT_NAME)
        run_results[kernel] = kernel.benchmark(args.runtime, args.n)

    if args.verbosity >= 0:
        print('Kernel:\tmin\tavg\tmax (Mhash/second)')
        print()
    for kernel, run_times in sorted(run_results.items(), key=lambda k: k[0].SHORT_NAME):
        print('%s:\t%.3f\t%.3f\t%.3f' % (
                    kernel.SHORT_NAME,
                    min(run_times) / 1000000,
                    (sum(run_times) / len(run_times)) / 1000000,
                    max(run_times)/1000000,
                ))

def cmd_listkernels(args):
    all_kernels = timelock.kernel.AlgorithmSHA256.KERNELS
    for kernel in sorted(all_kernels, key=lambda k: k.SHORT_NAME):
        print('%s - %s' % (kernel.SHORT_NAME, kernel.DESCRIPTION))

def cmd_create(args):
    delay = float(args.delay[:-1])
    delay_units = args.delay[-1].lower()
    if delay_units == 's':
        delay *= 1
    elif delay_units == 'm':
        delay *= 60
    elif delay_units == 'h':
        delay *= 60*60
    elif delay_units == 'd':
        delay *= 60*60*24
    elif delay_units == 'w':
        delay *= 60*60*24*7
    elif delay_units == 'y':
        delay *= 60*60*24*365
    else:
        logging.error("Unknown delay units '%s'; must be one of s/m/h/d/w/y" % delay_units)
        sys.exit(1)

    hash_rate = args.rate * 1000000

    per_chain_delay = delay / args.num_chains
    per_chain_n = int(hash_rate * per_chain_delay)

    print(per_chain_n)



parser = argparse.ArgumentParser(description='Timelock encryption tool')
parser.add_argument("-q","--quiet",action="count",default=0,
                             help="Be more quiet.")
parser.add_argument("-v","--verbose",action="count",default=0,
                             help="Be more verbose. Both -v and -q may be used multiple times.")

subparsers = parser.add_subparsers(title='Subcommands',
                                           description='All operations are done through subcommands:')

parser_listkernels = subparsers.add_parser('listkernels',
    help='List available kernels')
parser_listkernels.set_defaults(cmd_func=cmd_listkernels)
parser_listkernels.set_defaults(cmd_func=cmd_listkernels)

parser_benchmark = subparsers.add_parser('benchmark',
    help='Benchmark chain kernel(s)')
parser_benchmark.add_argument('-t', type=float, default=1.0, dest='runtime',
        help='Time to run each benchmark for')
parser_benchmark.add_argument('-n', type=int, default=5,
        help='# of runs per benchmark')
parser_benchmark.add_argument('kernel', nargs='*', metavar='KERNEL',
    help='Kernel to benchmark. May be specified multiple times; all available kernels if not specified.')
parser_benchmark.set_defaults(cmd_func=cmd_benchmark)

parser_create = subparsers.add_parser('create',
    help='Create a new timelock')
parser_create.add_argument('-n', type=int, default=10,
        dest='num_chains',
        help='# of parallel chains')
parser_create.add_argument('delay', type=str, metavar='DELAY[UNITS]',
        help='Desired unlocking delay')
parser_create.add_argument('rate', type=float, metavar='RATE',
        help='Estimated hashing rate of the unlocker in MHash/sec')
parser_create.add_argument('prefix', metavar='PREFIX',
        help='Path and prefix to use')
parser_create.set_defaults(cmd_func=cmd_create)

args = parser.parse_args()

args.verbosity = args.verbose - args.quiet

if args.verbosity == 1:
    logging.root.setLevel(logging.INFO)
elif args.verbosity > 2:
    logging.root.setLevel(logging.DEBUG)
elif args.verbosity == 0:
    logging.root.setLevel(logging.WARNING)
elif args.verbosity < 0:
    logging.root.setLevel(logging.ERROR)

args.cmd_func(args)
