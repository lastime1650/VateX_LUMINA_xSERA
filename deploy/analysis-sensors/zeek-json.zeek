# Load explicitly on an operator-managed passive Zeek sensor.
@load policy/tuning/json-logs
# Forward each log with its matching --zeek-kind; this is no capture setup.
