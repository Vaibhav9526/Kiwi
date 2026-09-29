// Ported from Mailspring `app/src/date-utils.ts` — the `shortTimeString`
// subset consumed by the thread-list columns. Adapted seams: `moment()`
// diff/isSame become native Date math; `AppEnv.config` resolves through
// the ms-keymap AppEnv shim's config surface (default: 12-hour clock,
// matching the vendor schema default for `core.workspace.use24HourClock`).
import { AppEnv } from "./ms-keymap";

function sameCalendarDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

export const DateUtils = {
  /**
   * Return a short format date/time
   *
   * @param {Date} datetime - Timestamp
   * @return {String} Formated date/time
   *
   * The returned date/time format depends on how long ago the timestamp is.
   */
  shortTimeString(datetime: Date) {
    const now = new Date();
    const diff = (now.getTime() - datetime.getTime()) / (1000 * 60 * 60 * 24);
    const isSameDay = sameCalendarDay(now, datetime);
    const opts: Intl.DateTimeFormatOptions = {
      hourCycle: AppEnv.config.get("core.workspace.use24HourClock") ? "h23" : "h12",
    };

    if (diff <= 1 && isSameDay) {
      // Time if less than 1 day old
      opts.hour = "numeric";
      opts.minute = "2-digit";
    } else if (diff < 5 && !isSameDay) {
      // Weekday with time if up to 2 days ago
      //opts.month = 'short';
      //opts.day = 'numeric';
      opts.weekday = "short";
      opts.hour = "numeric";
      opts.minute = "2-digit";
    } else {
      if (diff < 365) {
        // Month and day up to 1 year old
        opts.month = "short";
        opts.day = "numeric";
      } else {
        // Month, day and year if over a year old
        opts.year = "numeric";
        opts.month = "short";
        opts.day = "numeric";
      }
      return datetime.toLocaleDateString(navigator.language, opts);
    }

    return datetime.toLocaleTimeString(navigator.language, opts);
  },
};

export default DateUtils;
