# encoding: utf-8

require 'java'

# The CEF specification allows a variety of timestamp formats, some of which
# cannot be unambiguously parsed to a specific points in time, and may require
# additional side-channel information to do so, namely:
#  - the time zone or UTC offset (which MAY be included in a separate field)
#  - the locale (for parsing abbreviated month names)
#  - the year (assume "recent")
#
# This normalizer attempts to use the provided context and make reasonable
# assumptions when parsing ambiguous dates.
class LogStash::Codecs::CEF::TimestampNormalizer

  java_import java.time.Clock
  java_import java.time.LocalDate
  java_import java.time.LocalTime
  java_import java.time.MonthDay
  java_import java.time.OffsetDateTime
  java_import java.time.ZoneId
  java_import java.time.ZonedDateTime
  java_import java.time.format.DateTimeFormatter
  java_import java.util.Locale

  def initialize(locale:nil, timezone:nil, clock: Clock.systemUTC)
    @clock = clock

    java_locale   = locale ? get_locale(locale) : Locale.get_default
    java_timezone = timezone ? ZoneId.of(timezone) : ZoneId.system_default

    @cef_timestamp_format_parser = DateTimeFormatter
                                       .ofPattern("MMM dd[ yyyy] HH:mm:ss[.SSSSSSSSS][.SSSSSS][.SSS][ zzz]")
                                       .withZone(java_timezone)
                                       .withLocale(java_locale)
  end

  INTEGER_OR_DECIMAL_PATTERN = /\A[1-9][0-9]*(?:\.[0-9]+)?\z/
  private_constant :INTEGER_OR_DECIMAL_PATTERN

  # @param value [String,Time,Numeric]
  #   The value to parse. `Time`s are returned without modification, and `Numeric` values
  #   are treated as millis-since-epoch (as are fully-numeric strings).
  #   Strings are parsed unsing any of the supported CEF formats, and when the timestamp
  #   does not encode a year, we assume the year from contextual information like the
  #   current time.
  # @param device_timezone_name [String,nil] (optional):
  #   If known, the time-zone or UTC offset of the device that encoded the timestamp.
  #   This value is used to determine the offset when no offset is encoded in the timestamp.
  #   If not provided, the system default time zone is used instead.
  # @return [Time]
  def normalize(value, device_timezone_name=nil)
    return value if value.kind_of?(Time)

    case value
    when Numeric                    then Time.at(Rational(value, 1000))
    when INTEGER_OR_DECIMAL_PATTERN then Time.at(Rational(value, 1000))
    else
      parse_cef_format_string(value.to_s, device_timezone_name)
    end
  end

  private

  def get_locale(spec)
    if spec.nil?
      Locale.get_default
    elsif spec =~ /\A([a-z]{2})_([A-Z]{2})\z/
      lang, country = Regexp.last_match(1), Regexp.last_match(2)
      Locale.new(lang, country)
    else
      Locale.for_language_tag(spec)
    end
  end

  def parse_cef_format_string(value, context_timezone=nil)
    cef_timestamp_format_parser = @cef_timestamp_format_parser
    cef_timestamp_format_parser = cef_timestamp_format_parser.with_zone(java.time.ZoneId.of(context_timezone)) unless context_timezone.nil?

    parsed_time = cef_timestamp_format_parser.parse_best(value,
                                                         ->(v){ ZonedDateTime.from(v) },
                                                         ->(v){ OffsetDateTime.from(v) },
                                                         ->(v){ resolve_assuming_year(v) }).to_instant

    # Ruby's `Time::at(sec, microseconds_with_frac)`
    Time.at(parsed_time.get_epoch_second, Rational(parsed_time.get_nano, 1000))
  end

  def resolve_assuming_year(parsed_temporal_accessor)
    parsed_monthday = MonthDay.from(parsed_temporal_accessor)
    parsed_time = LocalTime.from(parsed_temporal_accessor)
    parsed_zone = ZoneId.from(parsed_temporal_accessor)

    now = ZonedDateTime.now(@clock.with_zone(parsed_zone))

    parsed_timestamp_with_current_year = ZonedDateTime.of(parsed_monthday.at_year(now.get_year), parsed_time, parsed_zone)

    if (parsed_timestamp_with_current_year > now.plus_days(2))
      # e.g., on May 12, parsing a date from May 15 or later is plausibly from
      # the prior calendar year and not actually from the future
      return ZonedDateTime.of(parsed_monthday.at_year(now.get_year - 1), parsed_time, parsed_zone)
    elsif now.get_month_value == 12 && (parsed_timestamp_with_current_year.plus_years(1) <= now.plus_days(2))
      # e.g., on December 31, parsing a date from January 1 could plausibly be
      # from the very-near future but next calendar year due to out-of-sync
      # clocks, mismatched timezones, etc.
      return ZonedDateTime.of(parsed_monthday.at_year(now.get_year + 1), parsed_time, parsed_zone)
    else
      # otherwise, assume current calendar year
      return parsed_timestamp_with_current_year
    end
  end
end
