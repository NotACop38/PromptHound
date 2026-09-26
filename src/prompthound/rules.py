"""Load and validate PromptHound Sigma rules.

A rule file holds either one detection (a *selection* rule) or one detection
plus one ``event_count`` correlation that references it. Loading a rule:

1. parses it with pySigma;
2. rejects detection features that PromptHound cannot evaluate offline *and*
   convert with identical semantics to Splunk and Sentinel (see
   ``_check_item`` and ``_check_negations``), and correlation shapes other than
   a single-base ``event_count`` over scalar fields;
3. validates the framework mappings in the rule's ``prompthound:`` block and
   its ATT&CK tags against :mod:`prompthound.taxonomy`;
4. compiles the detection into a predicate.

:func:`check_policy` adds the rules that apply to the published rule pack
(complete metadata, tenant-scoped correlations, pySigma's own validators).
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaError
from sigma.modifiers import (
    SigmaAllModifier,
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaGreaterThanEqualModifier,
    SigmaGreaterThanModifier,
    SigmaLessThanEqualModifier,
    SigmaLessThanModifier,
    SigmaStartswithModifier,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaString,
    SigmaType,
    SpecialChars,
)

from prompthound import fields, resources, taxonomy
from prompthound.correlate import OPERATORS, Correlation
from prompthound.matcher import Predicate, compile_rule, has_non_ascii_letter

Kind = Literal["selection", "correlation"]

#: Sigma levels, lowest to highest.
LEVELS = ("informational", "low", "medium", "high", "critical")

#: pySigma validators that fetch reference data over the network.
NETWORK_VALIDATORS = frozenset({"attacktag", "d3_fendtag"})

#: Every correlation in the published pack groups by tenant plus one of these.
IDENTITY_KEYS = ("user.id", "gen_ai.conversation.id")

#: Field types whose negated conditions behave identically in Splunk, KQL and Sigma.
_NEGATABLE = (("string",), ("boolean",))

_ALLOWED_MODIFIERS = (
    SigmaAllModifier,
    SigmaContainsModifier,
    SigmaStartswithModifier,
    SigmaEndswithModifier,
    SigmaGreaterThanModifier,
    SigmaGreaterThanEqualModifier,
    SigmaLessThanModifier,
    SigmaLessThanEqualModifier,
)
_MAPPING_KEYS = {
    "owasp_llm": taxonomy.OWASP_LLM,
    "owasp_agentic": taxonomy.OWASP_AGENTIC,
}


class RuleError(ValueError):
    """A rule file that cannot be loaded or uses unsupported Sigma features."""


@dataclass(frozen=True)
class Mappings:
    """Framework identifiers a rule is mapped to."""

    owasp_llm: tuple[str, ...] = ()
    owasp_agentic: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()


@dataclass(frozen=True, eq=False)
class Rule:
    """A loaded, validated rule and everything derived from it."""

    path: Path
    relpath: str
    id: str
    title: str
    status: str
    level: str
    description: str
    author: str
    date: dt.date | None
    modified: dt.date | None
    references: tuple[str, ...]
    falsepositives: tuple[str, ...]
    tags: tuple[str, ...]
    mappings: Mappings | None
    fields: tuple[str, ...]
    base: SigmaRule
    correlation: Correlation | None
    sigma_correlation: SigmaCorrelationRule | None
    predicate: Predicate

    @property
    def kind(self) -> Kind:
        return "selection" if self.correlation is None else "correlation"

    @property
    def category(self) -> str:
        return self.relpath.split("/", 1)[0]

    @property
    def stem(self) -> str:
        return Path(self.relpath).stem

    @property
    def content_fields(self) -> tuple[str, ...]:
        return tuple(f for f in self.fields if fields.get(f).data_class == "content")

    @property
    def derived_fields(self) -> tuple[str, ...]:
        return tuple(f for f in self.fields if fields.get(f).data_class == "derived")

    @property
    def requires_content(self) -> bool:
        return bool(self.content_fields)

    def matches(self, event: Any) -> bool:
        """Whether a single event satisfies the rule's detection (the base, for correlations)."""
        return self.predicate(event)


def load_rule(path: Path, root: Path) -> Rule:
    """Load and validate one rule file; ``root`` is the rule-pack directory."""
    relpath = path.relative_to(root).as_posix()
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except (SigmaError, yaml.YAMLError, OSError) as exc:
        raise RuleError(f"{relpath}: {exc}") from exc
    try:
        return _build(path, relpath, collection)
    except RuleError as exc:
        raise RuleError(f"{relpath}: {exc}") from None


def load_rules(directory: Path | None = None) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` rule under ``directory`` (default: the bundled pack)."""
    root = directory if directory is not None else resources.rules_dir()
    paths = sorted(p for p in root.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file())
    if not paths:
        raise RuleError(f"no rule files found under {root}")
    rules = [load_rule(path, root) for path in paths]
    for attribute in ("id", "title"):
        counts = Counter(getattr(rule, attribute) for rule in rules)
        duplicates = sorted(value for value, count in counts.items() if count > 1)
        if duplicates:
            raise RuleError(f"duplicate rule {attribute}(s): {', '.join(duplicates)}")
    return rules


def _build(path: Path, relpath: str, collection: SigmaCollection) -> Rule:
    bases = [r for r in collection.rules if isinstance(r, SigmaRule)]
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if (
        len(bases) != 1
        or len(correlations) > 1
        or len(collection.rules) != len(bases) + len(correlations)
    ):
        raise RuleError("a rule file holds one detection, optionally followed by one correlation")
    base = bases[0]
    if base.logsource.product != "llm_gateway":
        raise RuleError("logsource.product must be llm_gateway")
    for item in _detection_items(base):
        _check_item(item)
    for condition in base.detection.parsed_condition:
        _check_negations(condition.parse())

    sigma_correlation = correlations[0] if correlations else None
    correlation = _correlation(base, sigma_correlation) if sigma_correlation else None
    alerting = sigma_correlation or base

    referenced = {item.field for item in _detection_items(base) if item.field}
    if correlation:
        referenced.update(correlation.group_by)
    ordered = tuple(name for name in fields.registry() if name in referenced)

    return Rule(
        path=path,
        relpath=relpath,
        id=str(alerting.id),
        title=str(alerting.title),
        status=str(alerting.status.name.lower()) if alerting.status else "",
        level=str(alerting.level.name.lower()) if alerting.level else "",
        description=" ".join((alerting.description or "").split()),
        author=str(alerting.author or ""),
        date=alerting.date,
        modified=alerting.modified,
        references=tuple(str(r) for r in alerting.references),
        falsepositives=tuple(" ".join(str(f).split()) for f in alerting.falsepositives),
        tags=tuple(str(t) for t in alerting.tags),
        mappings=_mappings(alerting),
        fields=ordered,
        base=base,
        correlation=correlation,
        sigma_correlation=sigma_correlation,
        predicate=compile_rule(base),
    )


def _detection_items(rule: SigmaRule) -> Iterator[SigmaDetectionItem]:
    def walk(detection: SigmaDetection) -> Iterator[SigmaDetectionItem]:
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                yield from walk(item)
            else:
                yield item

    for detection in rule.detection.detections.values():
        yield from walk(detection)


def _check_item(item: SigmaDetectionItem) -> None:
    """Reject detection items whose semantics PromptHound cannot guarantee in every target."""
    if item.field is None:
        raise RuleError("keyword (field-less) detections are not supported")
    try:
        field = fields.get(item.field)
    except KeyError as exc:
        raise RuleError(str(exc.args[0])) from None
    unsupported = [m.__name__ for m in item.modifiers if not issubclass(m, _ALLOWED_MODIFIERS)]
    if unsupported:
        raise RuleError(f"{item.field}: unsupported modifier(s) {', '.join(unsupported)}")
    if field.is_timestamp:
        raise RuleError("timestamp cannot be used in a detection; time scoping is the SIEM's job")
    substring = (SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier)
    if (
        SigmaAllModifier in item.modifiers
        and not field.is_string_array
        and not any(issubclass(m, substring) for m in item.modifiers)
    ):
        # Kusto renders a plain "all" list as has_all, a term search rather than equality.
        raise RuleError(
            f"{item.field}: the all modifier needs a string-array field or contains, "
            "startswith or endswith"
        )
    for value in item.value:
        _check_value(field, value)


def _check_value(field: fields.Field, value: SigmaType) -> None:
    name = field.name
    if isinstance(value, SigmaNull):
        # Splunk counts an empty string as a value and an empty array as none;
        # KQL cannot tell a missing string from an empty one.
        raise RuleError(
            f"{name}: null checks are not supported, because Splunk and KQL disagree on "
            "which events lack a value; `prompthound readiness` reports missing fields"
        )
    if isinstance(value, SigmaString):
        if any(part is SpecialChars.WILDCARD_SINGLE for part in value.s):
            raise RuleError(f"{name}: '?' wildcards cannot be expressed in Splunk search")
        if not any(isinstance(part, str) and part for part in value.s):
            # KQL stores a missing string as "", which such a value would match.
            raise RuleError(
                f"{name}: a value needs a character other than '*'; "
                "existence checks are not supported"
            )
        if field.is_string_array:
            if value.contains_special():
                raise RuleError(f"{name}: string-array fields support exact element matching only")
            if has_non_ascii_letter(str(value)):
                raise RuleError(f"{name}: string-array values must not contain non-ASCII letters")
            return
        if field.is_content or field.types == ("string",):
            return
    elif isinstance(value, SigmaNumber | SigmaCompareExpression):
        # Comparisons come only from the allowed gt/gte/lt/lte modifiers.
        if field.types in (("integer",), ("number",)):
            return
    elif isinstance(value, SigmaBool):
        if field.types == ("boolean",):
            return
    raise RuleError(f"{name}: a {type(value).__name__} value does not fit a {field.types} field")


def _check_negations(node: object, negated: bool = False) -> None:
    """Reject negated conditions on numeric and string-array fields.

    Sigma treats a missing field as a non-match, so ``not`` matches events that
    lack the field. Splunk and KQL agree with that for strings and booleans, but
    both drop events without the field from a negated numeric comparison, and
    KQL (unlike Splunk) also drops them from a negated array-membership test.
    """
    if isinstance(node, ConditionAND | ConditionOR | ConditionNOT):
        for arg in node.args:
            _check_negations(arg, negated or isinstance(node, ConditionNOT))
    elif negated and isinstance(node, ConditionFieldEqualsValueExpression):
        field = fields.get(node.field)
        if field.is_string_array or not (field.is_content or field.types in _NEGATABLE):
            raise RuleError(
                f"{field.name}: a negated condition may only test string and boolean fields; "
                "Splunk and KQL disagree on events that lack this field (for a number, "
                "use the opposite comparison instead of not)"
            )


def _correlation(base: SigmaRule, rule: SigmaCorrelationRule) -> Correlation:
    if rule.type != SigmaCorrelationType.EVENT_COUNT:
        raise RuleError(f"unsupported correlation type {rule.type.name.lower()}")
    if rule.generate:
        raise RuleError("correlations must not set generate: true")
    if rule.aliases:
        raise RuleError("correlation aliases are not supported")
    references = rule.rules or []
    if len(references) != 1 or references[0].rule is not base:
        raise RuleError("a correlation must reference the detection in its own file")
    condition = rule.condition
    if not isinstance(condition, SigmaCorrelationCondition) or condition.fieldref is not None:
        raise RuleError("unsupported correlation condition")
    operator = condition.op.name.lower()
    if operator not in OPERATORS:
        raise RuleError(f"unsupported correlation operator {operator}")
    group_by = tuple(rule.group_by or ())
    for name in group_by:
        try:
            field = fields.get(name)
        except KeyError as exc:
            raise RuleError(str(exc.args[0])) from None
        if not field.is_scalar or field.is_timestamp or field.is_content:
            raise RuleError(f"group-by field {name!r} must be a scalar field other than timestamp")
    timespan = int(rule.timespan.seconds)
    if timespan <= 0 or 86400 % timespan:
        raise RuleError("timespan must divide one day evenly (fixed UTC windows)")
    return Correlation(
        group_by=group_by, timespan=timespan, operator=operator, threshold=condition.count
    )


def _mappings(rule: SigmaRule | SigmaCorrelationRule) -> Mappings | None:
    attack = []
    for tag in rule.tags:
        if tag.namespace != "attack":
            continue
        entry = tag.name.upper() if tag.name[:1] == "t" and tag.name[1:2].isdigit() else tag.name
        if entry not in taxonomy.ATTACK.entries:
            raise RuleError(f"ATT&CK tag attack.{tag.name} is not in the ATT&CK catalog")
        attack.append(entry)

    block = rule.custom_attributes.get("prompthound")
    if block is None:
        return Mappings(attack=tuple(attack)) if attack else None
    if not isinstance(block, dict):
        raise RuleError("the prompthound block must be a mapping")
    unknown = set(block) - {*_MAPPING_KEYS, "atlas"}
    if unknown:
        raise RuleError(f"unknown prompthound key(s): {', '.join(sorted(unknown))}")

    def ids(key: str, catalog: taxonomy.Taxonomy) -> tuple[str, ...]:
        values = block.get(key, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise RuleError(f"prompthound.{key} must be a list of identifiers")
        missing = [v for v in values if v not in catalog.entries]
        if missing:
            raise RuleError(
                f"prompthound.{key}: {', '.join(missing)} not in {catalog.name} {catalog.version}"
            )
        if len(set(values)) != len(values):
            raise RuleError(f"prompthound.{key} lists an identifier twice")
        return tuple(values)

    return Mappings(
        owasp_llm=ids("owasp_llm", taxonomy.OWASP_LLM),
        owasp_agentic=ids("owasp_agentic", taxonomy.OWASP_AGENTIC),
        atlas=ids("atlas", taxonomy.atlas()),
        attack=tuple(attack),
    )


def check_policy(rules: Sequence[Rule]) -> list[str]:
    """Publication requirements for a rule pack; returns human-readable violations."""
    from sigma.validation import SigmaValidator
    from sigma.validators.core import validators

    problems: list[str] = []
    for rule in rules:
        where = rule.relpath
        for attribute in ("title", "description", "author", "status", "level"):
            if not getattr(rule, attribute):
                problems.append(f"{where}: missing {attribute}")
        if rule.status not in {"experimental", "test", "stable"}:
            problems.append(f"{where}: status must be experimental, test or stable")
        if rule.date is None:
            problems.append(f"{where}: missing date")
        elif rule.modified is not None and rule.modified < rule.date:
            problems.append(f"{where}: modified precedes date")
        if not rule.references:
            problems.append(f"{where}: cite at least one reference")
        if not rule.falsepositives:
            problems.append(f"{where}: document false positives")
        if rule.mappings is None or not rule.mappings.owasp_llm:
            problems.append(f"{where}: map the rule to the OWASP Top 10 for LLM Applications")
        elif not (rule.mappings.atlas or rule.mappings.attack):
            problems.append(f"{where}: map the rule to at least one ATLAS or ATT&CK technique")
        if rule.category == "agent_tool_abuse" and not (
            rule.mappings and rule.mappings.owasp_agentic
        ):
            problems.append(f"{where}: agent rules must map to the OWASP Agentic Top 10")
        # pySigma rejects an identifier that is not a UUID, but not a missing one.
        if any(sigma_rule.id is None for sigma_rule in _documents(rule)):
            problems.append(f"{where}: every document needs an id")
        if rule.sigma_correlation is not None and rule.base.custom_attributes.get("prompthound"):
            problems.append(f"{where}: put metadata on the correlation, not its base detection")
        if rule.correlation is not None:
            keys = rule.correlation.group_by
            if "user.tenant.id" not in keys or not any(k in keys for k in IDENTITY_KEYS):
                problems.append(
                    f"{where}: correlations must group by user.tenant.id and "
                    f"{' or '.join(IDENTITY_KEYS)}"
                )

    # pySigma's own validators, except the two that download MITRE ATT&CK and
    # D3FEND data at run time (and cache it with diskcache). PromptHound checks
    # its ATT&CK tags against a pinned catalog instead, and the pack uses no
    # D3FEND tags, so validation stays offline.
    selected = [v for key, v in validators.items() if key not in NETWORK_VALIDATORS]
    documents = [doc for rule in rules for doc in _documents(rule)]
    # validate_rules is annotated for SigmaRule only but validates correlations too.
    for issue in SigmaValidator(selected).validate_rules(
        cast(Iterator[SigmaRule], iter(documents))
    ):
        affected = ", ".join(str(getattr(r, "title", "?")) for r in issue.rules)
        problems.append(
            f"pySigma {type(issue).__name__} ({issue.severity.name.lower()}): {affected}"
        )
    return problems


def _documents(rule: Rule) -> list[SigmaRule | SigmaCorrelationRule]:
    return [rule.base, rule.sigma_correlation] if rule.sigma_correlation else [rule.base]


__all__ = [
    "IDENTITY_KEYS",
    "LEVELS",
    "NETWORK_VALIDATORS",
    "Kind",
    "Mappings",
    "Rule",
    "RuleError",
    "check_policy",
    "load_rule",
    "load_rules",
]
