# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""Read-only connectors that turn a live target into a normalized snapshot.

Connectors are thin and optional: each imports its SDK lazily and degrades
gracefully (returns None / raises a clear error) when the SDK or credentials are
absent, so the framework stays dormant until a target is configured. All calls
are read-only (get/list/describe)."""
