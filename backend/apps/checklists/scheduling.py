from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import date, timedelta

from apps.checklists.models import ChecklistSchedule


WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def weekday_mask_for_date(d: date) -> int:
    # Python: Monday=0..Sunday=6
    return 1 << int(d.weekday())


def weekdays_from_mask(mask: int) -> list[int]:
    out: list[int] = []
    for i in range(0, 7):
        if int(mask) & (1 << i):
            out.append(i)
    return out


def first_weekday_offset(mask: int) -> int | None:
    for i in range(0, 7):
        if int(mask) & (1 << i):
            return i
    return None


def monday_of(d: date) -> date:
    return d - timedelta(days=int(d.weekday()))


def last_day_of_month(y: int, m: int) -> int:
    return int(monthrange(int(y), int(m))[1])


def add_months(y: int, m: int, delta: int) -> tuple[int, int]:
    """
    Add delta months to (y, m). Month is 1..12.
    """
    base = (int(y) * 12) + (int(m) - 1) + int(delta)
    ny = base // 12
    nm = (base % 12) + 1
    return int(ny), int(nm)


def months_index(d: date) -> int:
    return (int(d.year) * 12) + (int(d.month) - 1)


def next_occurrence_after(schedule: ChecklistSchedule, after: date) -> date:
    """
    Compute the next scheduled date strictly after `after`.
    """
    unit = (schedule.repeat_unit or ChecklistSchedule.REPEAT_DAILY).lower()
    interval = int(schedule.repeat_interval or 1)
    interval = max(1, min(3650, interval))

    anchor = schedule.anchor_on or schedule.next_run_on or after

    if unit == ChecklistSchedule.REPEAT_DAILY:
        return after + timedelta(days=interval)

    if unit == ChecklistSchedule.REPEAT_WEEKLY:
        mask = int(schedule.weekly_days or 0)
        if mask <= 0:
            # Fallback: preserve existing behavior by using anchor weekday.
            mask = weekday_mask_for_date(anchor)

        anchor_monday = monday_of(anchor)
        after_week_monday = monday_of(after)
        after_week_index = (after_week_monday - anchor_monday).days // 7

        # If current week is "active", see if there's another selected weekday later this week.
        if (after_week_index % interval) == 0:
            for off in range(int(after.weekday()) + 1, 7):
                if mask & (1 << off):
                    return after_week_monday + timedelta(days=off)

        # Jump to next active week and pick the first selected weekday in that week.
        mod = after_week_index % interval
        if mod == 0:
            next_week_index = after_week_index + interval
        else:
            next_week_index = after_week_index + (interval - mod)

        next_week_monday = anchor_monday + timedelta(weeks=int(next_week_index))
        first_off = first_weekday_offset(mask)
        if first_off is None:
            first_off = int(anchor.weekday())
        return next_week_monday + timedelta(days=int(first_off))

    if unit == ChecklistSchedule.REPEAT_MONTHLY:
        anchor_idx = months_index(anchor)
        after_idx = months_index(after)
        delta = after_idx - anchor_idx

        mod = delta % interval
        if mod == 0:
            next_delta = delta + interval
        else:
            next_delta = delta + (interval - mod)

        ny, nm = add_months(anchor.year, anchor.month, int(next_delta))
        last = last_day_of_month(ny, nm)

        if bool(schedule.monthly_on_last_day):
            day = last
        else:
            want = int(schedule.monthly_day or anchor.day or 1)
            want = max(1, min(31, want))
            day = min(want, last)

        return date(int(ny), int(nm), int(day))

    # Unknown unit: behave like daily.
    return after + timedelta(days=interval)


@dataclass
class AdvanceResult:
    changed: bool = False
    steps: int = 0


def advance_next_run_on(*, schedule: ChecklistSchedule, today: date) -> AdvanceResult:
    """
    Advance schedule.next_run_on until it's strictly after `today`.
    """
    changed = False
    steps = 0
    # Catch up in bounded steps to avoid pathological loops.
    for _ in range(0, 366):  # up to ~1 year of occurrences
        if schedule.next_run_on and schedule.next_run_on <= today:
            schedule.next_run_on = next_occurrence_after(schedule, schedule.next_run_on)
            changed = True
            steps += 1
            continue
        break
    return AdvanceResult(changed=changed, steps=steps)

