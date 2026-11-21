;; app unit: jolt.time.base
(define (jolt-app-init$jolt.time.base$0!)
(jolt-ns-load-vars-push!)
(set-chez-ns! "jolt.time.base")
(let ((_sr$ ((jolt-seed-root (jolt-var "clojure.core" "reset-meta!")) (let ((_sr$ ((jolt-seed-root (jolt-var "clojure.core" "create-ns")) (jolt-symbol #f "jolt.time.base")))) (set-virtual-register! 2 0) _sr$) (amap-slots->pmap (vector (keyword #f "doc") "Core-owned aggregator for the base java.time API \x2014; the portable value types\n  that compute from epoch arithmetic alone and need no OS timezone database or\n  locale data: Instant, LocalDate/LocalTime/LocalDateTime, Duration, Period,\n  Year/YearMonth/MonthDay, and the Month/DayOfWeek/Chrono* enums. Autoloaded on\n  first java.time.* use (see host/chez/java/host-static.ss), so date-free programs\n  pay nothing and a program that touches these gets them with no dependency.\n\n  Everything that formats or names a zone lives in the jolt-lang/time library,\n  which owns the single implementation of DateTimeFormatter, ZoneOffset/ZoneId,\n  ZonedDateTime/OffsetDateTime, localized formatting, java.util.Locale, and the\n  tick API. Core does not carry a second copy of any of those (RFC 0008)."))))) (set-virtual-register! 2 0) _sr$)
(jolt-ns-load-vars-pop!)
(jolt-startup-profile-mark! "namespace jolt.time.base")
)
