"""Evaluator framework to measure planner accuracy, efficiency, and resource metrics."""

from __future__ import annotations

import time

from pydantic import BaseModel, ConfigDict, Field

from src.models.agent import AgentState
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.planner.evaluation.dataset import EvaluationScenario
from src.planner.interfaces.planner import Planner
from src.planner.models.planner import ExecutionPlan, PlanningResult


class ScenarioEvaluationMetrics(BaseModel):
    """Metrics collected from running a single evaluation scenario."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scenario_name: str
    strategy_match: bool
    tool_precision: float
    tool_recall: float
    tool_f1: float
    false_positives: int
    false_negatives: int
    correctly_skipped_count: int
    planning_time_ms: int
    planner_confidence: float
    success: bool
    error_message: str | None = None


class OverallEvaluationReport(BaseModel):
    """Compiled metrics summary across all evaluated scenarios."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    total_scenarios: int
    success_rate: float
    average_planning_time_ms: float
    average_confidence: float
    strategy_accuracy: float
    average_tool_precision: float
    average_tool_recall: float
    average_tool_f1: float
    total_false_positives: int
    total_false_negatives: int
    total_correctly_skipped: int
    scenario_metrics: tuple[ScenarioEvaluationMetrics, ...] = Field(
        default_factory=tuple
    )


class PlannerEvaluator:
    """Evaluates Planner performance metrics against a list of scenarios."""

    def __init__(self, planner: Planner) -> None:
        self.planner = planner

    def evaluate_scenario(
        self, scenario: EvaluationScenario
    ) -> ScenarioEvaluationMetrics:
        """Run planner against a single email scenario and evaluate metrics."""
        # 1. Build EmailInput matching the scenario
        attachments = []
        for att in scenario.attachments:
            attachments.append(
                EmailAttachment(
                    filename=att.get("filename", "file"),
                    content_type=att.get("content_type", "application/octet-stream"),
                    size_bytes=att.get("size", 100),
                )
            )

        email = EmailInput(
            header=EmailHeader(
                message_id=scenario.headers.get("message_id", "<test-id>"),
                sender=scenario.headers.get("sender", "test@test.com"),
                recipients=[scenario.headers.get("recipient", "rec@test.com")],
                subject=scenario.headers.get("subject", "subject"),
                sent_at=scenario.headers.get("sent_at", "2026-07-28T12:00:00Z"),
            ),
            body_text=scenario.body,
            attachments=attachments,
        )

        state = AgentState.create(parsed_email=email)

        # 2. Run planning
        start_ns = time.perf_counter_ns()
        result: PlanningResult = self.planner.plan(state)
        planning_time_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))

        if not result.success or not result.plan:
            return ScenarioEvaluationMetrics(
                scenario_name=scenario.name,
                strategy_match=False,
                tool_precision=0.0,
                tool_recall=0.0,
                tool_f1=0.0,
                false_positives=0,
                false_negatives=0,
                correctly_skipped_count=0,
                planning_time_ms=planning_time_ms,
                planner_confidence=0.0,
                success=False,
                error_message=result.error_message or "Unknown planning error",
            )

        plan: ExecutionPlan = result.plan

        # 3. Calculate metrics
        strategy_match = plan.strategy.value == scenario.expected_strategy

        # Tools selected in the plan
        selected_tools = {s.tool for s in plan.steps}
        expected_tools = set(scenario.expected_tools)

        # Universe of potential tools
        all_possible_tools = {
            "parser_tool",
            "sender_tool",
            "url_tool",
            "attachment_tool",
        }

        # Calculate True Positives, False Positives, False Negatives, True Negatives
        tp = len(selected_tools.intersection(expected_tools))
        fp = len(selected_tools.difference(expected_tools))
        fn = len(expected_tools.difference(selected_tools))

        # Correctly skipped tools (tools that are NOT expected and NOT selected)
        not_expected = all_possible_tools.difference(expected_tools)
        tn = len(not_expected.difference(selected_tools))

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (
            (2 * precision * recall / (precision + recall))
            if (precision + recall) > 0
            else 1.0
        )

        return ScenarioEvaluationMetrics(
            scenario_name=scenario.name,
            strategy_match=strategy_match,
            tool_precision=round(precision, 2),
            tool_recall=round(recall, 2),
            tool_f1=round(f1, 2),
            false_positives=fp,
            false_negatives=fn,
            correctly_skipped_count=tn,
            planning_time_ms=planning_time_ms,
            planner_confidence=round(plan.confidence, 2),
            success=True,
        )

    def evaluate_all(
        self, scenarios: list[EvaluationScenario]
    ) -> OverallEvaluationReport:
        """Run evaluation metrics over all scenarios in the dataset."""
        metrics_list = []
        for scen in scenarios:
            metrics_list.append(self.evaluate_scenario(scen))

        total_scenarios = len(scenarios)
        successful_scenarios = [m for m in metrics_list if m.success]

        if not successful_scenarios:
            return OverallEvaluationReport(
                total_scenarios=total_scenarios,
                success_rate=0.0,
                average_planning_time_ms=0.0,
                average_confidence=0.0,
                strategy_accuracy=0.0,
                average_tool_precision=0.0,
                average_tool_recall=0.0,
                average_tool_f1=0.0,
                total_false_positives=0,
                total_false_negatives=0,
                total_correctly_skipped=0,
                scenario_metrics=tuple(metrics_list),
            )

        success_rate = (len(successful_scenarios) / total_scenarios) * 100.0
        avg_time = sum(m.planning_time_ms for m in successful_scenarios) / len(
            successful_scenarios
        )
        avg_conf = sum(m.planner_confidence for m in successful_scenarios) / len(
            successful_scenarios
        )
        strat_acc = (
            sum(1 for m in successful_scenarios if m.strategy_match)
            / len(successful_scenarios)
            * 100.0
        )
        avg_prec = sum(m.tool_precision for m in successful_scenarios) / len(
            successful_scenarios
        )
        avg_rec = sum(m.tool_recall for m in successful_scenarios) / len(
            successful_scenarios
        )
        avg_f1 = sum(m.tool_f1 for m in successful_scenarios) / len(
            successful_scenarios
        )

        total_fp = sum(m.false_positives for m in successful_scenarios)
        total_fn = sum(m.false_negatives for m in successful_scenarios)
        total_tn = sum(m.correctly_skipped_count for m in successful_scenarios)

        return OverallEvaluationReport(
            total_scenarios=total_scenarios,
            success_rate=round(success_rate, 1),
            average_planning_time_ms=round(avg_time, 1),
            average_confidence=round(avg_conf, 2),
            strategy_accuracy=round(strat_acc, 1),
            average_tool_precision=round(avg_prec, 2),
            average_tool_recall=round(avg_rec, 2),
            average_tool_f1=round(avg_f1, 2),
            total_false_positives=total_fp,
            total_false_negatives=total_fn,
            total_correctly_skipped=total_tn,
            scenario_metrics=tuple(metrics_list),
        )
