from __future__ import annotations

from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem


def copy_checklist_items_to_run(*, org, run: ChecklistRun, checklist: Checklist) -> int:
    """
    Copy template items into a run (bounded).
    """

    items = list(ChecklistItem.objects.filter(organization=org, checklist=checklist).order_by("sort_order", "id")[:2000])
    created = 0
    for it in items:
        ChecklistRunItem.objects.create(
            organization=org,
            run=run,
            checklist_item=it,
            text=it.text,
            sort_order=int(it.sort_order or 0),
        )
        created += 1
    return created

