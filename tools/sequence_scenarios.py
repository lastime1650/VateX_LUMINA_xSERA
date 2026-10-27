"""Compatibility command for the generator shipped with the installed package."""

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sapientia.sequence_samples import (
    CONTEXTS as CONTEXTS,
    FAMILIES as FAMILIES,
    MECHANISMS as MECHANISMS,
    OFFSETS as OFFSETS,
    PARTITIONS as PARTITIONS,
    SCHEMA as SCHEMA,
    digest as digest,
    generate as generate,
    main as main,
    validate as validate,
    write_dataset as write_dataset,
)

if __name__ == "__main__":
    main()
