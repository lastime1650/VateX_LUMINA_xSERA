"""Immediate failure evidence for long isolated regression runs."""
def pytest_runtest_logreport(report):
    if report.failed:
        print("\nREGRESSION_FAILURE: "+report.nodeid+" ["+report.when+"]",flush=True)
        print(str(report.longrepr),flush=True)
