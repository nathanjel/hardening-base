"""Config loading: defaults manage nothing, the host file overlays them."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "lib"))
from hbkit import config  # noqa: E402


class ConfigTest(unittest.TestCase):
    def load_text(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        os.environ["HB_CONFIG"] = f.name
        self.addCleanup(os.environ.pop, "HB_CONFIG")
        return config.load()

    def test_defaults_manage_nothing(self):
        cfg = self.load_text("")
        self.assertEqual(config.get(cfg, "harden.remove_accounts"), [])
        self.assertEqual(config.get(cfg, "harden.remove_files"), [])
        self.assertEqual(config.get(cfg, "harden.permit_root_login"), "")
        self.assertEqual(config.get(cfg, "k8s.nodeport_addresses"), [])
        self.assertEqual(config.get(cfg, "k8s.token_off_namespaces"), [])

    def test_host_file_overlays_one_key(self):
        cfg = self.load_text('[k8s]\nnodeport_addresses = ["127.0.0.0/8"]\n')
        self.assertEqual(config.get(cfg, "k8s.nodeport_addresses"), ["127.0.0.0/8"])
        self.assertEqual(config.get(cfg, "k8s.flavour"), "microk8s")

    def test_unknown_key_raises(self):
        with self.assertRaises(KeyError):
            config.get(self.load_text(""), "k8s.nope")

    def test_unknown_keys_flags_typos(self):
        data = {"harden": {"remove_acounts": []}, "extra": {}}
        self.assertEqual(sorted(config.unknown_keys(data)), ["extra", "harden.remove_acounts"])

    def test_free_form_tables_hold_any_names(self):
        data = {"fw": {"zones": {"public": {"services": []}, "my-zone": {}}, "revert_minutes": 5}}
        self.assertEqual(config.unknown_keys(data), [])
        self.assertEqual(config.unknown_keys({"fw": {"zone": {}}}), ["fw.zone"])

    def test_defaults_not_mutated_by_load(self):
        self.load_text('[harden]\nremove_accounts = ["x"]\n')
        self.assertEqual(config.DEFAULTS["harden"]["remove_accounts"], [])

    def test_example_file_has_no_unknown_keys(self):
        example = os.path.join(config.REPO, "hb.toml.example")
        with open(example, "rb") as f:
            self.assertEqual(config.unknown_keys(config.tomllib.load(f)), [])


if __name__ == "__main__":
    unittest.main()
