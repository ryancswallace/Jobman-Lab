#!/usr/bin/env python3
"""Read synthetic Lab configuration without accessing credentials or guests."""
import argparse
import json
from pathlib import Path
import sys

from lab_configuration import load, inventory_variables
from jobman_config import ConfigurationError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['document', 'inventory-vars', 'get'])
    parser.add_argument('key', nargs='?')
    parser.add_argument('--root')
    parser.add_argument('--absolute', action='store_true')
    args = parser.parse_args()
    try:
        document, root = load(args.root)
        if args.command == 'document':
            print(json.dumps(document))
        elif args.command == 'inventory-vars':
            print(json.dumps(inventory_variables(document)))
        else:
            if not args.key:
                raise ConfigurationError('get requires a dotted configuration key')
            value = document
            for key in args.key.split('.'):
                value = value[key]
            if isinstance(value, (dict, list)):
                print(json.dumps(value))
            else:
                if args.absolute:
                    if not isinstance(value, str) or not value:
                        raise ConfigurationError('required local path is unset; supply an external versions.yml')
                    value = str((root / value).resolve())
                print(value)
        return 0
    except (ConfigurationError, OSError, KeyError, TypeError):
        print('lab-config: invalid or incomplete synthetic configuration; inspect the selected files', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
