"""Descriptions for defensive junk templates.

Templates are metadata only. They describe where platform/compiler agents may
insert misleading structure, while keeping behavior-preserving constraints and
forbidden actions explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TemplateClass(str, Enum):
    IRREDUCIBLE_CFG = "irreducible_cfg"
    VM_STUB_JUNK = "vm_stub_junk"
    HANDLER_JUNK = "handler_junk"
    FAKE_OPCODE_HANDLER = "fake_opcode_handler"
    FAKE_XREF_LAYOUT = "fake_xref_layout"


@dataclass(frozen=True)
class JunkTemplate:
    template_id: str
    template_class: TemplateClass
    description: str
    insertion_points: tuple[str, ...]
    invariants: tuple[str, ...]
    forbidden_behaviors: tuple[str, ...]
    estimated_cost: int


class JunkTemplateCatalog:
    """Catalog for T060-T064 template descriptions."""

    def __init__(self, templates: tuple[JunkTemplate, ...] | None = None) -> None:
        self._templates = templates if templates is not None else DEFAULT_TEMPLATES

    def all(self) -> tuple[JunkTemplate, ...]:
        return self._templates

    def by_class(self, template_class: TemplateClass) -> tuple[JunkTemplate, ...]:
        return tuple(template for template in self._templates if template.template_class == template_class)

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        seen: set[str] = set()
        for template in self._templates:
            if template.template_id in seen:
                errors.append(f"duplicate template id: {template.template_id}")
            seen.add(template.template_id)
            if template.estimated_cost < 1:
                errors.append(f"{template.template_id}: estimated_cost must be positive")
            if not template.invariants:
                errors.append(f"{template.template_id}: invariants are required")
            if not template.forbidden_behaviors:
                errors.append(f"{template.template_id}: forbidden behaviors are required")
        return tuple(errors)


COMMON_FORBIDDEN = (
    "no persistence, privilege escalation, stealth installation, or security-product bypass",
    "no network activity, process injection, credential access, or destructive behavior",
    "no platform probing in template metadata",
)

DEFAULT_TEMPLATES = (
    JunkTemplate(
        template_id="cfg.loop_interlock.v1",
        template_class=TemplateClass.IRREDUCIBLE_CFG,
        description="Introduce behavior-preserving multi-entry CFG regions around protected blocks.",
        insertion_points=("post-flatten protected functions", "VM control-check regions"),
        invariants=("original observable behavior is unchanged", "all inserted paths terminate or rejoin"),
        forbidden_behaviors=COMMON_FORBIDDEN,
        estimated_cost=3,
    ),
    JunkTemplate(
        template_id="stub.opaque_dispatch.v1",
        template_class=TemplateClass.VM_STUB_JUNK,
        description="Wrap VM entry stubs with opaque state setup and non-semantic dispatch noise.",
        insertion_points=("VM entry stubs", "call bridge prelude"),
        invariants=("VM context ABI fields are not reordered", "external call ABI remains unchanged"),
        forbidden_behaviors=COMMON_FORBIDDEN,
        estimated_cost=2,
    ),
    JunkTemplate(
        template_id="handler.dead_lane.v1",
        template_class=TemplateClass.HANDLER_JUNK,
        description="Add unreachable or semantically neutral lanes to bytecode handlers.",
        insertion_points=("handler bodies", "handler dispatch epilogue"),
        invariants=("opcode semantics stay identical", "handler table indices remain valid"),
        forbidden_behaviors=COMMON_FORBIDDEN,
        estimated_cost=2,
    ),
    JunkTemplate(
        template_id="opcode.decoy_handler.v1",
        template_class=TemplateClass.FAKE_OPCODE_HANDLER,
        description="Describe fake handlers that share layout traits with real handlers but are never selected.",
        insertion_points=("randomized handler table padding", "unused opcode ranges"),
        invariants=("decoy opcodes are unreachable from valid bytecode", "invalid opcode handling is deterministic"),
        forbidden_behaviors=COMMON_FORBIDDEN,
        estimated_cost=1,
    ),
    JunkTemplate(
        template_id="xref.readonly_alias.v1",
        template_class=TemplateClass.FAKE_XREF_LAYOUT,
        description="Place read-only aliases that may confuse static xref recovery without affecting runtime data.",
        insertion_points=("read-only metadata sections", "protected report side tables"),
        invariants=("aliases are non-authoritative", "runtime never trusts fake xref metadata"),
        forbidden_behaviors=COMMON_FORBIDDEN,
        estimated_cost=1,
    ),
)
