from __future__ import annotations

from dataclasses import dataclass

from django import forms
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from .models import Relationship


@dataclass(frozen=True)
class ParsedRef:
    content_type: ContentType
    object_id: str
    label: str


def parse_object_ref(ref: str) -> ParsedRef:
    """
    Parse refs like: "assets.asset:12" or "docsapp.document:3".
    """

    ref = (ref or "").strip()
    if not ref or ":" not in ref or "." not in ref:
        raise ValidationError('Invalid ref. Expected "app_label.model:pk" (example: "assets.asset:12").')

    left, pk = ref.split(":", 1)
    pk = pk.strip()
    if not pk:
        raise ValidationError('Invalid ref. Missing ":pk" portion.')
    app_label, model = left.split(".", 1)
    app_label = app_label.strip()
    model = model.strip()
    if not app_label or not model:
        raise ValidationError('Invalid ref. Expected "app_label.model:pk".')

    try:
        ct = ContentType.objects.get(app_label=app_label, model=model)
    except ContentType.DoesNotExist as e:
        raise ValidationError(f"Unknown content type: {app_label}.{model}") from e

    model_cls = ct.model_class()
    if model_cls is None:
        raise ValidationError(f"Content type has no model class: {app_label}.{model}")

    try:
        obj = model_cls.objects.get(pk=pk)
    except model_cls.DoesNotExist as e:
        raise ValidationError(f"Object not found: {app_label}.{model}:{pk}") from e

    return ParsedRef(content_type=ct, object_id=str(obj.pk), label=str(obj))


class RelationshipAdminForm(forms.ModelForm):
    source_ref = forms.CharField(
        required=True,
        help_text='Format: "app_label.model:pk" (example: "assets.asset:12").',
    )
    target_ref = forms.CharField(
        required=True,
        help_text='Format: "app_label.model:pk" (example: "docsapp.document:3").',
    )

    class Meta:
        model = Relationship
        fields = [
            "organization",
            "relationship_type",
            "source_ref",
            "target_ref",
            "notes",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        inst: Relationship | None = kwargs.get("instance")
        if inst and inst.pk:
            self.fields["source_ref"].initial = f"{inst.source_content_type.app_label}.{inst.source_content_type.model}:{inst.source_object_id}"
            self.fields["target_ref"].initial = f"{inst.target_content_type.app_label}.{inst.target_content_type.model}:{inst.target_object_id}"

    def clean(self):
        cleaned = super().clean()

        src = parse_object_ref(cleaned.get("source_ref") or "")
        tgt = parse_object_ref(cleaned.get("target_ref") or "")

        cleaned["source_content_type"] = src.content_type
        cleaned["source_object_id"] = src.object_id
        cleaned["target_content_type"] = tgt.content_type
        cleaned["target_object_id"] = tgt.object_id

        # Avoid self-links.
        if src.content_type.id == tgt.content_type.id and src.object_id == tgt.object_id:
            raise ValidationError("Relationship cannot point to the same object.")

        return cleaned

    def save(self, commit=True):
        inst: Relationship = super().save(commit=False)
        inst.source_content_type = self.cleaned_data["source_content_type"]
        inst.source_object_id = self.cleaned_data["source_object_id"]
        inst.target_content_type = self.cleaned_data["target_content_type"]
        inst.target_object_id = self.cleaned_data["target_object_id"]
        if commit:
            inst.save()
            self.save_m2m()
        return inst

