from pathlib import Path

from anti_analysis import JunkTemplateCatalog, TemplateClass


def test_default_catalog_is_valid() -> None:
    catalog = JunkTemplateCatalog()

    assert catalog.validate() == ()


def test_catalog_covers_plan_template_classes() -> None:
    catalog = JunkTemplateCatalog()

    for template_class in TemplateClass:
        assert catalog.by_class(template_class), template_class


def test_templates_keep_safety_forbidden_behaviors_visible() -> None:
    catalog = JunkTemplateCatalog()

    for template in catalog.all():
        joined = " ".join(template.forbidden_behaviors)
        assert "persistence" in joined
        assert "security-product bypass" in joined
        assert "process injection" in joined


def test_templates_cover_audit_forbidden_terms_fixture() -> None:
    catalog = JunkTemplateCatalog()
    terms = Path("tests/audit/anti_analysis/forbidden_terms.txt").read_text(encoding="utf-8").splitlines()

    for template in catalog.all():
        joined = " ".join(template.forbidden_behaviors)
        for term in terms:
            assert term in joined
