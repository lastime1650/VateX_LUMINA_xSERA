"""Additive backend initialization; all native/external effects stay opt-in."""

def initialize(store):
    from . import action_runtime, connector_runtime, correlation_runtime, effect_receipts, event_projections, qualification_registry, source_registry, record_governance, detector_ops
    for module in (source_registry, qualification_registry, effect_receipts, connector_runtime, event_projections, correlation_runtime, action_runtime, detector_ops, record_governance):
        module.initialize(store)
