# Robot Work Permit — publicly reproducible **offline simulation**

This copies the bounded PR #122 experiment for public inspection, **without physical hardware**, ROS 2 deployment, real workcell instructions or physical safety certification. `receiver_a.py` is a fictional ROS2-style action receiver, `receiver_b.py` an independently written REST-style fleet receiver, and `conventional_receiver.py` a competent non-OpenLine comparator. Each receiver uses its own policy enforcement and a separate simulated controller SQLite journal. This code is not connected to the `accept.v1` procurement wire format.

From the exported source root (`cryptography>=38,<51` installed):

```sh
python examples/robotics_sim/conformance.py --target A
python examples/robotics_sim/conformance.py --target B
python examples/robotics_sim/conformance.py --target V
python examples/robotics_sim/negative_control.py  # MUST exit 1, and show 0/4
python examples/robotics_sim/test_boundaries.py
python -O examples/robotics_sim/test_boundaries.py
```

All three good implementations must pass 14/14 independently observed simulated-controller cases, including fresh-nonce revoked-worker refusal, post-commit crash, successor recovery, configuration changes and effects without controller admission. The defective C profile must be caught. Published result values are not a substitute for actually executing the commands.

**Limitations:** A simulated controller journal and receiver signature do not establish real robot motion, safe hardware effects, vendor interoperability, or external exactly-once execution. The public artifact includes independent receiver and conventional code, rather than pretending one universal domain wire protocol has been proven.
