# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""
AWS Encryption SDK Encrypt Message manifest handler.
"""
import json
import os

from awses_test_vectors.util import algorithm_suite_from_string_id, validate_manifest_type
from awses_test_vectors.manifests.keys import KeysManifest
from awses_test_vectors.manifests.master_key import MasterKeySpec

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Dict, IO  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (1,)


class EncryptTestScenario(object):
    """"""

    @classmethod
    def from_scenario(cls, scenario, keys, plaintexts):
        instance = cls()
        instance.plaintext = plaintexts[scenario['plaintext']]
        instance.algorithm = algorithm_suite_from_string_id(scenario['algorithm'])
        instance.frame_size = scenario['frame-size']
        instance.encryption_context = scenario['encryption-context']
        master_keys = [MasterKeySpec.from_scenario_spec(spec).master_key(keys) for spec in scenario['master-keys']]
        primary = master_keys[0]
        others = master_keys[1:]
        for master_key in others:
            primary.add_master_key_provider(master_key)
        instance.master_key_provider = primary
        return instance


class EncryptMessageManifest(object):
    """"""
    type_name = 'awses-encrypt'

    @staticmethod
    def _load_keys(parent_dir, keys_uri):
        # type: (str, str) -> KeysManifest
        """"""
        if not keys_uri.startswith('file://'):
            raise ValueError('Only file URIs are supported at this time.')

        with open(os.path.join(parent_dir, keys_uri[len('file://'):])) as keys_file:
            raw_manifest = json.load(keys_file)
            return KeysManifest.from_raw_manifest(raw_manifest)

    @staticmethod
    def _generate_plaintexts(plaintexts_specs):
        # type: (Dict[str, int]) -> Dict[str, bytes]
        """Generate required plaintext values.

        :param dict plaintexts_specs: Mapping of plaintext name to size in bytes
        :return: Mapping of plaintext name to randomly generated bytes
        :rtype: dict
        """
        # generate and return rather than being a generator because we need
        # the values to actually be generated immediately
        plaintexts = {}
        for name, size in plaintexts_specs.items():
            plaintexts[name] = os.urandom(size)
        return plaintexts

    @classmethod
    def from_file(cls, input_file):
        # type: (IO) -> EncryptMessageManifest
        """"""
        raw_manifest = json.load(input_file)
        validate_manifest_type(
            type_name=cls.type_name,
            manifest=raw_manifest,
            supported_versions=SUPPORTED_VERSIONS
        )
        instance = cls()
        instance.version = raw_manifest['manifest']['version']
        parent_dir = os.path.abspath(os.path.dirname(input_file.name))
        instance.keys = instance._load_keys(parent_dir, raw_manifest['keys'])
        instance.plaintexts = instance._generate_plaintexts(raw_manifest['plaintexts'])
        instance.tests = [
            EncryptTestScenario.from_scenario(
                scenario=scenario,
                keys=instance.keys,
                plaintexts=instance.plaintexts
            )
            for scenario in raw_manifest['tests']
        ]
        return instance

    def write_to_dir(self, target_directory):
        """"""
