"""Blast radius classification logic."""

from __future__ import annotations

from .models import (
    ActionCategory,
    ClassificationResult,
    DataTier,
    NodeBlastDetail,
    NodeId,
    NodeMetadata,
    SoakParams,
    TraversalResult,
    ACTION_SEVERITY,
)

__all__ = ["classify_blast", "classify_node"]


def classify_node(
    detail: NodeBlastDetail,
    metadata: NodeMetadata,
    low_trust_threshold: float = 0.3,
) -> ActionCategory:
    """Classify a single node's ActionCategory.

    Rules (evaluated in priority order):
      - unauthorized tier -> HUMAN_GATE
      - low-trust authoritative -> HUMAN_GATE
      - FINANCIAL / AUTH / COMPLIANCE -> HUMAN_GATE
      - PII -> SOAK
      - PUBLIC -> AUTO_MERGE
    """
    if detail.node_id != metadata.node_id:
        raise ValueError(
            f"node_id mismatch: detail has {detail.node_id!r}, "
            f"metadata has {metadata.node_id!r}"
        )

    # Unauthorized tier
    if metadata.data_tier not in metadata.authorized_tiers:
        return ActionCategory.HUMAN_GATE

    # Low-trust authoritative
    if metadata.is_authoritative and metadata.trust_score < low_trust_threshold:
        return ActionCategory.HUMAN_GATE

    # Tier-based classification
    if metadata.data_tier in (DataTier.FINANCIAL, DataTier.AUTH, DataTier.COMPLIANCE):
        return ActionCategory.HUMAN_GATE

    if metadata.data_tier == DataTier.PII:
        return ActionCategory.SOAK

    # PUBLIC (or any other tier that fell through)
    return ActionCategory.AUTO_MERGE


def _classify_detail(
    detail: NodeBlastDetail,
    low_trust_threshold: float,
) -> ActionCategory:
    """Classify a single node from its blast detail fields.

    This mirrors classify_node but works directly from NodeBlastDetail
    fields so that classify_blast does not require full NodeMetadata.
    """
    if not detail.is_authorized_for_tier:
        return ActionCategory.HUMAN_GATE

    if detail.is_authoritative and detail.trust_score < low_trust_threshold:
        return ActionCategory.HUMAN_GATE

    if detail.data_tier in (DataTier.FINANCIAL, DataTier.AUTH, DataTier.COMPLIANCE):
        return ActionCategory.HUMAN_GATE

    if detail.data_tier == DataTier.PII:
        return ActionCategory.SOAK

    return ActionCategory.AUTO_MERGE


def classify_blast(
    traversal: TraversalResult,
    soak_params: SoakParams,
) -> ClassificationResult:
    """Classify a blast radius traversal result.

    Re-classifies each node using detail fields and low_trust_threshold
    from soak_params, then takes the max over all per-node ActionCategory
    values. legal_flag is True iff action==HUMAN_GATE and at least one
    reachable node has COMPLIANCE tier.
    """
    if not traversal.reachable_nodes:
        raise ValueError(
            f"Empty traversal result for origin {traversal.origin!r}"
        )

    max_action = ActionCategory.AUTO_MERGE
    contributing: list[NodeId] = []
    has_compliance = False

    for detail in traversal.node_details:
        node_action = _classify_detail(detail, soak_params.low_trust_threshold)

        if ACTION_SEVERITY[node_action] > ACTION_SEVERITY[max_action]:
            max_action = node_action
            contributing = [detail.node_id]
        elif node_action == max_action:
            contributing.append(detail.node_id)

        if detail.data_tier == DataTier.COMPLIANCE:
            has_compliance = True

    legal_flag = max_action == ActionCategory.HUMAN_GATE and has_compliance

    return ClassificationResult(
        action=max_action,
        legal_flag=legal_flag,
        contributing_nodes=contributing,
    )
