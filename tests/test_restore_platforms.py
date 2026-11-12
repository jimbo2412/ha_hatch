"""The original Hatch Restore (product ``restore``) across every platform.

Runs each platform's setup against a real hatch_rest_api Restore whose MQTT
shadow client is stubbed out. Needs homeassistant and hatch_rest_api from
requirements.txt; skipped without them, like a checkout with no dev install.
"""

import asyncio
import sys
import unittest
from concurrent.futures import Future
from importlib.util import find_spec
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parents[1]))

HAS_DEPENDENCIES = all(
    find_spec(name) is not None for name in ("homeassistant", "hatch_rest_api")
)

if HAS_DEPENDENCIES:
    from hatch_rest_api import RestMini, Restore

    from custom_components.ha_hatch import (
        binary_sensor,
        diagnostics,
        light,
        media_player,
        number,
        scene,
        select,
        sensor,
        switch,
        time,
    )
    from custom_components.ha_hatch.const import DOMAIN
    from custom_components.ha_hatch.media_rest_entity import MediaRestEntity

    PLATFORMS = {
        "binary_sensor": binary_sensor,
        "light": light,
        "media_player": media_player,
        "number": number,
        "scene": scene,
        "select": select,
        "sensor": sensor,
        "switch": switch,
        "time": time,
    }

RESTORE_STATE = {
    "connected": True,
    "rssi": -44,
    "deviceInfo": {"f": "3.2.1", "fR": 1, "hwVersion": "R1"},
    "content": {"playing": "routine", "step": 2, "routineId": 123456, "paused": False},
    "sound": {"id": 10005, "v": 19660, "enabled": True},
    "color": {"id": 3, "i": 32767, "enabled": True},
    "headphones": {
        "requestedPin": "1234",
        "connectedMacAddress": "00:11:22:33:44:55",
        "stateResult": "unknown",
    },
}


def _done(result=None) -> Future:
    future: Future = Future()
    future.set_result(result)
    return future


class StubShadowClient:
    """IotShadowClient stub that records the desired state of each update."""

    def __init__(self):
        self.published = []

    def subscribe_to_update_shadow_accepted(self, request, qos, callback):
        return _done(), "update-topic"

    def subscribe_to_get_shadow_accepted(self, request, qos, callback):
        return _done(), "get-topic"

    def publish_get_shadow(self, request, qos):
        return _done(MagicMock())

    def publish_update_shadow(self, request, qos):
        self.published.append(request.state.desired)
        return _done()


class FakeCoordinator:
    def __init__(self, rest_devices):
        self.rest_devices = rest_devices

    def rest_device_by_thing_name(self, thing_name):
        return next(
            (device for device in self.rest_devices if device.thing_name == thing_name),
            None,
        )

    def async_add_alarm_refresh_callback(self, callback):
        return lambda: None


def _device(device_class, thing_name, mac):
    client = StubShadowClient()
    device = device_class(
        device_name="Bedroom",
        thing_name=thing_name,
        mac=mac,
        shadow_client=client,
    )
    return device, client


def _set_up_platforms(rest_devices) -> dict[str, list]:
    """Run every platform's async_setup_entry; return the entities each added."""
    coordinator = FakeCoordinator(rest_devices)
    hass = SimpleNamespace(data={DOMAIN: coordinator})
    config_entry = SimpleNamespace(options={}, async_on_unload=lambda remove: None)
    added: dict[str, list] = {}

    async def set_up_all():
        for name, platform in PLATFORMS.items():
            added[name] = []
            await platform.async_setup_entry(hass, config_entry, added[name].extend)

    # The alarm reconcilers prune the entity registry, which needs a real hass.
    with (
        patch.object(switch, "remove_stale_alarm_entities"),
        patch.object(switch, "update_alarm_entity_names"),
        patch.object(sensor, "remove_stale_alarm_entities"),
        patch.object(sensor, "update_alarm_entity_names"),
        patch.object(time, "remove_stale_alarm_entities"),
        patch.object(time, "update_alarm_entity_names"),
    ):
        asyncio.run(set_up_all())
    return added


@unittest.skipUnless(HAS_DEPENDENCIES, "needs homeassistant and hatch_rest_api")
class RestorePlatformSetupTest(unittest.TestCase):
    def setUp(self):
        self.restore, self.client = _device(Restore, "thing-restore", "11:22:33:44:55:66")
        self.restore._update_local_state(RESTORE_STATE)
        self.added = _set_up_platforms([self.restore])

    def _entity(self, platform, unique_id):
        return next(
            entity for entity in self.added[platform] if entity.unique_id == unique_id
        )

    def test_creates_only_the_restore_entities(self):
        self.assertEqual(
            {
                platform: sorted(type(entity).__name__ for entity in entities)
                for platform, entities in self.added.items()
            },
            {
                "binary_sensor": ["HatchOnlineSensor"],
                "light": [],
                "media_player": [],
                "number": [],
                "scene": [],
                "select": [],
                "sensor": [
                    "HatchFirmwareVersion",
                    "HatchRestorePlaying",
                    "HatchSignalStrength",
                ],
                "switch": ["HatchRestoreRoutineSwitch"],
                "time": [],
            },
        )

    def test_unique_ids(self):
        self.assertEqual(
            sorted(
                entity.unique_id
                for entities in self.added.values()
                for entity in entities
            ),
            [
                "thing-restore_bedtime_routine",
                "thing-restore_firmware_version",
                "thing-restore_playing",
                "thing-restore_wifi",
                "thing-restore_wifi_signal",
            ],
        )

    def test_routine_switch(self):
        routine = self._entity("switch", "thing-restore_bedtime_routine")
        self.assertEqual(routine.name, "Bedroom Bedtime Routine")
        self.assertIs(routine.is_on, True)

        routine.turn_off()
        routine.turn_on()

        self.assertEqual(
            self.client.published,
            [
                {"content": {"playing": "none", "paused": False, "offset": 0, "step": 0}},
                {"content": {"playing": "routine", "paused": False, "offset": 0, "step": 1}},
            ],
        )

        self.restore._update_local_state({"content": {"playing": "none"}})
        self.assertIs(routine.is_on, False)

    def test_playing_sensor(self):
        playing = self._entity("sensor", "thing-restore_playing")
        self.assertEqual(playing.native_value, "routine")
        self.assertEqual(playing.icon, "mdi:play-circle-outline")
        self.assertEqual(
            playing.extra_state_attributes,
            {"step": 2, "routine_id": 123456, "paused": False},
        )

        self.restore._update_local_state({"content": {"playing": "none"}})
        self.assertEqual(playing.native_value, "none")
        self.assertEqual(playing.icon, "mdi:stop-circle-outline")

    def test_diagnostic_sensors(self):
        firmware = self._entity("sensor", "thing-restore_firmware_version")
        signal = self._entity("sensor", "thing-restore_wifi_signal")
        self.assertEqual(firmware.native_value, "3.2.1")
        self.assertEqual(signal.native_value, -44)
        self.assertEqual(signal.native_unit_of_measurement, "dBm")

    def test_connectivity(self):
        online = self._entity("binary_sensor", "thing-restore_wifi")
        self.assertIs(online.is_on, True)


@unittest.skipUnless(HAS_DEPENDENCIES, "needs homeassistant and hatch_rest_api")
class RestoreMediaPlayerTest(unittest.TestCase):
    def test_restore_gets_no_media_player(self):
        restore, _ = _device(Restore, "thing-restore", "11:22:33:44:55:66")
        rest_mini, _ = _device(RestMini, "thing-mini", "AA:BB:CC:DD:EE:FF")
        coordinator = FakeCoordinator([restore, rest_mini])

        def choose(device):
            return media_player.choose_media_entity(
                device, config_turn_on_media=True, coordinator=coordinator
            )

        self.assertIsNone(choose(restore))
        # The guard must not swallow the models that do fall through.
        self.assertIsInstance(choose(rest_mini), MediaRestEntity)


@unittest.skipUnless(HAS_DEPENDENCIES, "needs homeassistant and hatch_rest_api")
class RestoreDiagnosticsTest(unittest.TestCase):
    def test_carries_the_raw_shadow_without_headphone_secrets(self):
        restore, _ = _device(Restore, "thing-restore", "11:22:33:44:55:66")
        restore._update_local_state(RESTORE_STATE)
        device_registry = MagicMock()
        device_registry.async_get_device.return_value = None
        hass = SimpleNamespace(data={DOMAIN: FakeCoordinator([restore])})
        config_entry = MagicMock()
        config_entry.as_dict.return_value = {"data": {}}

        with (
            patch.object(diagnostics.dr, "async_get", return_value=device_registry),
            patch.object(diagnostics.er, "async_get", return_value=MagicMock()),
        ):
            data = asyncio.run(
                diagnostics.async_get_config_entry_diagnostics(hass, config_entry)
            )

        shadow = data["thing-restore"]["shadow_state"]
        self.assertEqual(shadow["content"]["routineId"], 123456)
        self.assertEqual(shadow["headphones"]["stateResult"], "unknown")
        self.assertEqual(shadow["headphones"]["requestedPin"], "**REDACTED**")
        self.assertEqual(
            shadow["headphones"]["connectedMacAddress"], "**REDACTED**"
        )
        # Redacting a copy: the device keeps its real state.
        self.assertEqual(restore.shadow_state["headphones"]["requestedPin"], "1234")


if __name__ == "__main__":
    unittest.main()
