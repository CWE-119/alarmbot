"""Calendar anchored reminder scheduling, independent of Discord and storage."""
import calendar
import re
import warnings
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil import parser
from dateutil.tz import datetime_exists, resolve_imaginary

UTC = timezone.utc
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_MESSAGE = 1200


def utcnow():
    return datetime.now(UTC)


def iso(value):
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def as_utc(value):
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def timezone_for(name):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("Use a timezone such as Asia/Dhaka or America/New_York.") from exc


def localize(value, tz):
    """First fold for repeated times; move nonexistent times forward by the DST gap."""
    if value.tzinfo is not None:
        return value.astimezone(tz)
    result = value.replace(tzinfo=tz, fold=0)
    return resolve_imaginary(result) if not datetime_exists(result) else result


def parse_duration(text):
    match = re.fullmatch(r"\s*(\d{1,8})\s*(m|min|mins|minutes?|h|hr|hrs|hours?|d|days?|w|weeks?)\s*", text.lower())
    if not match:
        return None
    number = int(match[1])
    unit = match[2][0]
    seconds = number * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return timedelta(seconds=seconds) if 0 < seconds <= 365 * 86400 else None


def parse_when(text, tz, now=None):
    now = (now or utcnow()).astimezone(tz)
    text = text.strip().lower()
    if text.startswith("in "):
        delta = parse_duration(text[3:])
        return (now.astimezone(UTC) + delta).astimezone(tz) if delta else None
    if not text:
        return None
    base = now.replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
    explicit_day = False
    for word, days in (("today ", 0), ("tomorrow ", 1)):
        if text.startswith(word):
            text = text[len(word):]
            base += timedelta(days=days)
            explicit_day = True
            break
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", parser.UnknownTimezoneWarning)
            parsed = parser.parse(text, fuzzy=False, default=base)
        when = localize(parsed, tz)
        # Only a bare clock time rolls over; explicit past dates are never silently changed.
        clock_only = bool(re.fullmatch(r"\d{1,2}(?::\d{2}(?::\d{2})?)?\s*(?:am|pm)?", text))
        if when <= now and clock_only and not explicit_day:
            when = localize(parsed.replace(tzinfo=None) + timedelta(days=1), tz)
        return when if when > now else None
    except (ValueError, OverflowError, parser.UnknownTimezoneWarning):
        return None


def normalize_repeat(value):
    value = (value or "once").strip().lower()
    if value in {"once", "off", "none"}:
        return None
    if value in {"daily", "weekly", "weekdays", "monthly"}:
        return value
    days = value.removeprefix("days=").split(",")
    if days and all(day.strip()[:3] in DAY_NAMES for day in days):
        return ",".join(day for day in DAY_NAMES if day in {d.strip()[:3] for d in days})
    raise ValueError("Repeat: once, daily, weekly, weekdays, monthly, or mon,wed,fri.")


def validate_message(message):
    message = message.strip() or "Alarm!"
    if len(message) > MAX_MESSAGE:
        raise ValueError(f"Reminder messages may contain at most {MAX_MESSAGE} characters.")
    return message


def parse_alarm_args(raw, tz, now=None):
    left, separator, message = raw.partition("|")
    tokens = left.split()
    repeat = None  # None means omitted; 'once' explicitly turns repeating off on edit.
    for index in range(len(tokens)-1):
        if [token.lower() for token in tokens[index:index+2]] == ["repeat", "off"]:
            repeat = "once"
            del tokens[index:index+2]
            break
    for index, token in enumerate(tokens):
        if token.lower() in {"daily", "weekly", "weekdays", "monthly", "once", "off"} or re.fullmatch(r"(?:days=)?(?:mon|tue|wed|thu|fri|sat|sun)(?:,(?:mon|tue|wed|thu|fri|sat|sun))*", token.lower()):
            repeat = normalize_repeat(token) or "once"
            del tokens[index]
            break
    when = None
    if separator:
        when = parse_when(" ".join(tokens), tz, now)
    else:
        for size in range(min(len(tokens), 8), 0, -1):
            when = parse_when(" ".join(tokens[:size]), tz, now)
            if when:
                message = " ".join(tokens[size:])
                break
    if when is None:
        raise ValueError("Use a future time: tomorrow 9am, 15:30, or in 2h. Put | before the message.")
    return when, repeat, validate_message(message) if message.strip() else None


def anchor_for(when, tz_name):
    return when.astimezone(timezone_for(tz_name)).replace(tzinfo=None).isoformat()


def next_occurrence(anchor, tz_name, repeat, after):
    """First occurrence strictly after after, preserving original wall time and month day."""
    repeat = normalize_repeat(repeat)
    if not repeat:
        return None
    start = datetime.fromisoformat(anchor).replace(tzinfo=None)
    tz = timezone_for(tz_name)
    after = as_utc(after)
    day = max(start.date(), after.astimezone(tz).date())
    if repeat == "monthly":
        month = max(start.year * 12 + start.month - 1, day.year * 12 + day.month - 1)
        for offset in range(14):
            year, zero_month = divmod(month + offset, 12)
            month_number = zero_month + 1
            candidate = start.replace(year=year, month=month_number, day=min(start.day, calendar.monthrange(year, month_number)[1]))
            when = localize(candidate, tz).astimezone(UTC)
            if candidate >= start and when > after:
                return when
    else:
        allowed = set(range(7)) if repeat == "daily" else ({start.weekday()} if repeat == "weekly" else set(range(5)) if repeat == "weekdays" else {DAY_NAMES.index(d) for d in repeat.split(",")})
        for offset in range(9):
            date = day + timedelta(days=offset)
            candidate = datetime.combine(date, start.time())
            when = localize(candidate, tz).astimezone(UTC)
            if candidate >= start and date.weekday() in allowed and when > after:
                return when
    raise ValueError("The next reminder date is outside the supported calendar.")


def first_occurrence(when, tz_name, repeat):
    if normalize_repeat(repeat):
        return next_occurrence(anchor_for(when, tz_name), tz_name, repeat, when - timedelta(microseconds=1))
    return when.astimezone(UTC)


def quiet_end(now, tz_name, start, end):
    """Return a UTC defer time when inside quiet hours, otherwise None."""
    if not start or not end:
        return None
    tz = timezone_for(tz_name)
    local = now.astimezone(tz)
    clock = local.strftime("%H:%M")
    overnight = start > end
    inside = start <= clock < end if not overnight else clock >= start or clock < end
    if not inside:
        return None
    date = local.date() + timedelta(days=1 if overnight and clock >= start else 0)
    hour, minute = map(int, end.split(":"))
    finish = localize(datetime.combine(date, datetime.min.time()).replace(hour=hour, minute=minute), tz)
    # During the second repeated hour, the first fold may already be in the past.
    if finish.astimezone(UTC) <= now:
        finish = finish.replace(fold=1)
    return finish.astimezone(UTC)


def validate_quiet(start, end):
    if start.lower() == "off":
        return None, None
    if not all(re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value or "") for value in (start, end)) or start == end:
        raise ValueError("Use different HH:MM times, such as 22:00 and 08:00, or off.")
    return start, end
