# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Torrust project contributors

"""The carrier cites (´claim:carrier:python-method-documentation-is-citable´)."""

import unittest


class DocstringCarrier(unittest.TestCase):
    """The carrier area cites (´claim:carrier:python-method-documentation-is-citable´)."""

    def test_python_claim_is_carried(self):
        """A Python method's documentation supplies a citable claim.

        ´claim:carrier:python-method-documentation-is-citable´
        ´test:integration:test-python-claim-is-carried´
        """
        lines = [line.strip() for line in self.test_python_claim_is_carried.__doc__.splitlines()
                 if line.strip()]
        claim = "´claim:carrier:python-method-documentation-is-citable´"
        self.assertEqual(lines[-2], claim)
        name = self.test_python_claim_is_carried.__name__.replace("_", "-")
        self.assertEqual(lines[-1], "´test:integration:" + name + "´")
        self.assertIn("(" + claim + ")", __doc__)
        self.assertIn("(" + claim + ")", type(self).__doc__)
