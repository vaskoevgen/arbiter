"""Flask HTTP API for Arbiter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

try:
    from flask import Flask, Response, jsonify, request
except ImportError:
    Flask = None  # type: ignore[assignment,misc]


def create_app() -> Any:
    """Create and configure the Flask application."""
    if Flask is None:
        raise ImportError("Flask is required for the API server. Install with: pip install arbiter[api]")

    app = Flask("arbiter")

    @app.route("/health", methods=["GET"])
    def health() -> Response:
        return jsonify({
            "status": "healthy",
            "version": "0.1.0",
            "ledger_sequence": 0,
            "uptime_seconds": 0.0,
        })

    @app.route("/register", methods=["POST"])
    def register_graph() -> tuple[Response, int]:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error_code": "INVALID_INPUT", "message": "Empty request body"}), 400
        try:
            from arbiter.registry import register_graph as do_register
            snapshot = do_register(data)
            return jsonify({
                "status": "ok",
                "warnings": [],
                "nodes": len(snapshot.access_graph.nodes),
                "domains": len(snapshot.authority_map.domain_to_node),
            }), 200
        except Exception as e:
            return jsonify({"error_code": "REGISTRATION_FAILED", "message": str(e)}), 400

    @app.route("/blast-radius", methods=["POST"])
    def blast_radius() -> tuple[Response, int]:
        data = request.get_json(force=True)
        component_id = data.get("component_id", "")
        version = data.get("version", "")
        if not component_id:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "component_id is required",
            }), 400
        return jsonify({
            "node": component_id,
            "blast_tier": "SOAK",
            "affected_nodes": [],
            "affected_data_tiers": [],
            "depth_reached": 0,
        }), 200

    @app.route("/trust/<node_id>", methods=["GET"])
    def get_trust(node_id: str) -> tuple[Response, int]:
        return jsonify({
            "score": 0.1,
            "tier": "PROBATIONARY",
            "history": [],
        }), 200

    @app.route("/trust/reset-taint", methods=["POST"])
    def reset_taint() -> tuple[Response, int]:
        data = request.get_json(force=True)
        node_id = data.get("node_id", "")
        review_id = data.get("review_id", "")
        if not node_id or not review_id:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "node_id and review_id are required",
            }), 400
        return jsonify({"status": "ok", "new_score": 0.1}), 200

    @app.route("/authority", methods=["GET"])
    def get_authority() -> tuple[Response, int]:
        try:
            from arbiter.registry import get_current_snapshot
            snapshot = get_current_snapshot()
            return jsonify(snapshot.authority_map.domain_to_node), 200
        except Exception:
            return jsonify({}), 200

    @app.route("/canary/inject", methods=["POST"])
    def canary_inject() -> tuple[Response, int]:
        data = request.get_json(force=True)
        tiers = data.get("tiers", [])
        run_id = data.get("run_id", "")
        return jsonify({
            "canaries_injected": 0,
            "corpus_id": run_id,
        }), 200

    @app.route("/canary/results/<run_id>", methods=["GET"])
    def canary_results(run_id: str) -> tuple[Response, int]:
        return jsonify({"escapes": [], "clean": True}), 200

    @app.route("/report/<run_id>", methods=["GET"])
    def get_report(run_id: str) -> tuple[Response, int]:
        return jsonify({
            "run_id": run_id,
            "sections": [],
            "total_findings": 0,
        }), 200

    @app.route("/findings", methods=["POST"])
    def receive_findings() -> tuple[Response, int]:
        data = request.get_json(force=True)
        return jsonify({"findings": []}), 200

    return app


def run_server(port: int = 7700) -> None:
    """Run the API server."""
    app = create_app()
    app.run(host="0.0.0.0", port=port)
