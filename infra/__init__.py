# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
SecureScope infrastructure security assessment.

A pluggable, read-only posture-assessment framework for running infrastructure
(hypervisors, storage, physical/BMC, network, identity, OS/DB). Assessors are
pure functions over a normalized *snapshot* dict, so they are fully unit-tested
against fixtures with no live infrastructure. Live collection is done by thin,
optional connectors that degrade gracefully when their SDK or credentials are
absent — the framework is dormant until a target is configured.

See docs/INFRASTRUCTURE-ASSESSMENT.md for the architecture.
"""

from .base import (
    Finding, Target, Assessor, register, get_assessors, assessors_for_kind,
    assess_snapshot, summarize, posture_grade,
)

# Importing an assessor module registers it (side effect).
from . import vmware  # noqa: F401

__all__ = [
    "Finding", "Target", "Assessor", "register", "get_assessors",
    "assessors_for_kind", "assess_snapshot", "summarize", "posture_grade",
]
