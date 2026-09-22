import unittest
from datetime import datetime

import gui_dashboard


class ThresholdBehaviorTests(unittest.TestCase):
    def test_save_threshold_updates_live_alert_setting(self):
        mon = gui_dashboard.TrafficMonitor(threshold=50)
        self.assertEqual(mon.threshold, 50)

        mon.threshold = 100
        mon.port_counts["80"] = 99
        mon._check_alert(datetime.now(), "80")

        self.assertEqual(mon.alert_total, 1)
        self.assertEqual(mon.alerts[0]["port"], "80")
        self.assertEqual(mon.alerts[0]["packets"], 100)

    def test_check_alert_fires_when_count_exceeds_threshold(self):
        mon = gui_dashboard.TrafficMonitor(threshold=100)
        mon.port_counts["80"] = 124
        mon._check_alert(datetime.now(), "80")

        self.assertEqual(mon.alert_total, 1)
        self.assertEqual(mon.alerts[0]["packets"], 125)

    def test_dashboard_does_not_auto_start_capture_on_open(self):
        with open("gui_dashboard.py", "r", encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("self.after(1000, lambda: self.set_capture(True))", source)

    def test_pie_layout_uses_canvas_bounds(self):
        layout = gui_dashboard.pie_layout(170, 170)
        self.assertGreaterEqual(layout["r"], 40)
        self.assertLessEqual(layout["cx"] + layout["r"], 170)
        self.assertLessEqual(layout["cy"] + layout["r"], 170)

    def test_map_layout_keeps_node_positions_inside_canvas(self):
        layout = gui_dashboard.map_layout(280, 150, 4)
        self.assertEqual(len(layout["x_positions"]), 4)
        self.assertTrue(all(0 <= x <= 280 for x in layout["x_positions"]))
        self.assertGreater(layout["device_y"], layout["router_y"])

    def test_toggle_monitoring_switches_active_state(self):
        class DummyMonitor:
            def __init__(self, running=False):
                self.running = running

            def start(self):
                self.running = True

            def stop(self):
                self.running = False

        class DummyWidget:
            def __init__(self):
                self.kwargs = {}

            def config(self, **kwargs):
                self.kwargs.update(kwargs)

        class DummyVar:
            def __init__(self, value=""):
                self.value = value

            def set(self, value):
                self.value = value

        app = gui_dashboard.App.__new__(gui_dashboard.App)
        app.mon = DummyMonitor(running=False)
        app.live_dot = DummyWidget()
        app.v_live = DummyVar(" Monitoring Stopped")
        app.status_msg = DummyVar("Stopped")
        app.cap_buttons = [(DummyWidget(), DummyWidget())]

        app.toggle_monitoring()

        self.assertTrue(app.mon.running)
        self.assertEqual(app.v_live.value, " Monitoring Active")
        self.assertEqual(app.status_msg.value, "Capturing packets...")


if __name__ == "__main__":
    unittest.main()
