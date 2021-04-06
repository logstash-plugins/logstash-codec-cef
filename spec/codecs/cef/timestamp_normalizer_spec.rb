# encoding: utf-8

require 'logstash/util'
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/codecs/cef"
require 'logstash/codecs/cef/timestamp_normalizer'

describe LogStash::Codecs::CEF::TimestampNormalizer do

  subject(:timestamp_normalizer) { described_class.new }
  let(:parsed_result) { timestamp_normalizer.normalize(parsable_string) }

  context "parsing dates with a year specified" do
    let(:parsable_string) { "Jun 17 2027 17:57:06.456" }
    it 'parses the year correctly' do
      expect(parsed_result.year).to eq(2027)
    end
  end

  context "unparsable inputs" do
    let(:parsable_string) { "Last Thursday" }
    it "raises a StandardError exception that can be caught upstream" do
      expect { parsed_result }.to raise_error(StandardError, /#{Regexp::escape parsable_string}/)
    end
  end

  context "side-channel time zone indicators" do
    let(:context_timezone) { 'America/New_York' }
    let(:parsed_result) { timestamp_normalizer.normalize(parsable_string, context_timezone) }

    context "when parsed input does not include offset information" do
      let(:parsable_string) { "Jun 17 2027 17:57:06.456" }

      it 'offsets to the context timezone time' do
        expect(parsed_result).to eq(Time.parse("2027-06-17T21:57:06.456Z"))
      end
    end
    context "when parsed input includes offset information" do
      let(:parsable_string) { "Jun 17 2027 17:57:06.456 -07:00" }

      it 'uses the parsed offset' do
        expect(parsed_result).to eq(Time.parse("2027-06-18T00:57:06.456Z"))
      end
    end
    context "when parsed input is a millis-since-epoch timestamp" do
      let(:parsable_string) { "1616623591694" }

      it "does not offset the time" do
        expect(parsed_result).to eq(Time.at(Rational(1616623591694,1_000)))
        expect(parsed_result.nsec).to eq(694_000_000)
      end
    end
    context "when parsed input is a millis-since-epoch timestamp with decimal part and microsecond precision" do
      let(:parsable_string) { "1616623591694.176" }

      it "does not offset the time" do
        expect(parsed_result).to eq(Time.at(Rational(1616623591694176,1_000_000)))
        expect(parsed_result.nsec).to eq(694_176_000)
      end
    end
    context "when parsed input is a millis-since-epoch timestamp with decimal part and nanosecond precision" do
      let(:parsable_string) { "1616623591694.176789" }

      it "does not offset the time" do
        expect(parsed_result).to eq(Time.at(Rational(1616623591694176789,1_000_000_000)))
        expect(parsed_result.nsec).to eq(694_176_789)
      end
    end
  end

  context "when locale is specified" do
    let(:locale_language) { 'de' }
    let(:locale_country) { 'DE' }
    let(:locale_spec) { "#{locale_language}_#{locale_country}" }

    # Due to locale-provider loading changes in JDK 9, abbreviations for months
    # depend on a combination of the JDK version and the `java.locale.providers`
    # system property.
    # Instead of hard-coding a localized month name, use this process's locales
    # to generate one.
    let(:java_locale) { java.util.Locale.new(locale_language, locale_country) }
    let(:localized_march_abbreviation) do
      months = java.text.DateFormatSymbols.new(java_locale).get_short_months
      months[2] # march
    end

    subject(:timestamp_normalizer) { described_class.new(locale: locale_spec) }

    let(:parsable_string) { "#{localized_march_abbreviation} 17 2019 17:57:06.456 +01:00" }

    it 'uses the locale to parse the date' do
      expect(parsed_result).to eq(Time.parse("2019-03-17T17:57:06.456+01:00"))
    end
  end

  context "parsing dates with sub-second precision" do
    context "whole second precision" do
      let(:parsable_string) { "Mar 17 2021 12:34:56 +00:00" }
      it "is accurate to the second" do
        expect(parsed_result.nsec).to eq(000_000_000)
        expect(parsed_result).to eq(Time.parse("2021-03-17T12:34:56Z"))
      end
    end
    context "millisecond sub-second precision" do
      let(:parsable_string) { "Mar 17 2021 12:34:56.987" }
      let(:format_string) { "%b %d %H:%M:%S.%3N" }
      it "is accurate to the millisecond" do
        expect(parsed_result.nsec).to eq(987_000_000)
        expect(parsed_result).to eq(Time.parse("2021-03-17T12:34:56.987Z"))
      end
    end
    context "microsecond sub-second precision" do
      let(:parsable_string) { "Mar 17 2021 12:34:56.987654" }
      let(:format_string) { "%b %d %H:%M:%S.%6N" }
      it "is accurate to the microsecond" do
        expect(parsed_result.nsec).to eq(987_654_000)
        expect(parsed_result).to eq(Time.parse("2021-03-17T12:34:56.987654Z"))
      end
    end
    context "nanosecond sub-second precision" do
      let(:parsable_string) { "Mar 17 2021 12:34:56.987654321" }
      let(:format_string) { "%b %d %H:%M:%S.%9N" }
      it "is accurate to the nanosecond" do
        expect(parsed_result.nsec).to eq(987_654_321)
        expect(parsed_result).to eq(Time.parse("2021-03-17T12:34:56.987654321Z"))
      end
    end
  end

  context "parsing dates with no year specified" do
    let(:time_of_parse) { fail(NotImplementedError) }
    let(:format_to_parse) { "%b %d %H:%M:%S.%3N" }
    let(:offset_days) { fail(NotImplementedError) }
    let(:time_to_parse) { (time_of_parse + (offset_days * 86400)) }
    let(:parsable_string) { time_to_parse.strftime(format_to_parse) }


    let(:anchored_clock) do
      instant = java.time.Instant.of_epoch_second(time_of_parse.to_i)
      zone = java.time.ZoneId.system_default

      java.time.Clock.fixed(instant, zone)
    end

    subject(:timestamp_normalizer) { described_class.new(clock: anchored_clock) }

    let(:parsed_result) { timestamp_normalizer.normalize(parsable_string) }

    context 'when parsing a date during late December' do
      let(:time_of_parse) { Time.parse("2020-12-31T23:53:08.123456789Z") }
      context 'and handling a date string from early january' do
        let(:time_to_parse) { Time.parse("2021-01-01T00:00:08.123456789Z") }
        it 'assumes that the date being parsed is in the very near future' do
          expect(parsed_result.month).to eq(1)
          expect(parsed_result.year).to eq(time_of_parse.year + 1)
        end
      end
      context 'and handling a yearless date string from mid january' do
        let(:time_to_parse) { Time.parse("2021-01-17T00:00:08.123456789Z") }
        it 'assumes that the date being parsed is in the distant past' do
          $stderr.puts(parsable_string)
          expect(parsed_result.month).to eq(1)
          expect(parsed_result.year).to eq(time_of_parse.year)
        end
      end
    end

    # As a smoke test to validate the guess-the-year feature when the provided CEF timestamp
    # does not include the year, we iterate through a variety of dates that we want to parse,
    # and with each of them we parse with a mock clock as if we were performing the parsing
    # operation at a variety of date-times relative to the timestamp represented.
    %w(
      2021-01-20T04:10:22.961Z
      2021-06-08T03:38:55.518Z
      2021-07-12T18:46:12.149Z
      2021-08-12T04:17:36.680Z
      2021-08-12T13:20:14.951Z
      2021-09-17T13:18:57.534Z
      2021-09-23T16:35:40.404Z
      2021-10-30T18:52:29.263Z
      2021-11-11T00:52:39.409Z
      2021-11-19T13:37:07.189Z
      2021-12-02T01:09:21.846Z
      2021-12-11T16:35:05.641Z
      2021-12-15T14:17:22.152Z
      2021-12-19T05:53:57.200Z
      2021-12-20T16:18:17.637Z
      2021-12-22T12:06:48.965Z
      2021-12-26T04:45:14.964Z
      2022-01-05T09:42:39.895Z
      2022-02-02T04:58:22.080Z
      2022-02-05T08:10:15.386Z
      2022-02-15T16:48:27.083Z
      2022-02-31T13:26:55.298Z
      2022-03-10T20:16:25.732Z
      2022-03-20T23:38:58.734Z
      2022-03-30T03:42:09.546Z
      2022-04-09T05:55:18.697Z
      2022-04-14T05:05:29.278Z
      2022-04-25T15:29:19.567Z
      2022-05-02T08:34:21.666Z
      2022-05-24T02:59:02.257Z
      2022-07-25T01:58:35.713Z
      2022-07-27T03:27:57.568Z
      2022-07-28T20:28:22.704Z
      2022-09-21T08:59:10.508Z
      2022-10-29T23:54:02.372Z
      2022-11-12T15:22:51.758Z
      2022-11-22T22:02:33.278Z
      2022-12-30T03:18:38.333Z
      2023-01-02T16:55:57.829Z
      2023-01-13T16:37:38.078Z
      2023-01-27T07:27:09.296Z
      2023-01-30T17:56:43.665Z
      2023-02-18T11:41:18.886Z
      2023-02-28T18:51:59.504Z
      2023-03-10T06:52:14.285Z
      2023-04-17T16:25:06.489Z
      2023-04-18T20:46:29.611Z
      2023-04-27T10:21:41.036Z
      2023-05-08T02:54:57.131Z
      2023-05-13T01:17:37.396Z
      2023-05-24T18:23:05.136Z
      2023-06-01T11:09:48.129Z
      2023-06-22T07:44:56.876Z
      2023-06-25T20:17:44.394Z
      2023-06-25T20:53:36.329Z
      2023-07-24T13:07:58.536Z
      2023-07-27T21:35:54.299Z
      2023-08-07T11:15:33.803Z
      2023-08-12T18:45:46.791Z
      2023-08-19T23:22:19.717Z
      2023-08-22T23:19:41.075Z
      2023-08-25T15:22:47.405Z
      2023-09-03T14:34:13.345Z
      2023-09-28T05:48:20.040Z
      2023-09-29T21:14:15.531Z
      2023-11-12T21:25:55.233Z
      2023-11-30T00:41:21.834Z
      2023-12-11T10:14:51.676Z
      2023-12-14T18:02:33.005Z
      2023-12-18T09:00:43.589Z
      2023-12-20T20:02:42.205Z
      2023-12-22T10:13:37.553Z
      2023-12-27T19:42:37.905Z
      2023-12-31T17:52:50.101Z
      2024-02-29T01:23:45.678Z
    ).map {|ts| Time.parse(ts) }.each do |timestamp|
      cef_parsable_timestamp = timestamp.strftime("%b %d %H:%M:%S.%3N Z")

      context "when parsing the string `#{cef_parsable_timestamp}`" do

        let(:expected_result) { timestamp }
        let(:parsable_string) { cef_parsable_timestamp }

        {
          'very recent past'      =>       -30.789, # ~ 30 seconds ago
          'somewhat recent past'  =>   -608976.678, # ~ 1 week days ago
          'distant past'          => -29879991.916, # ~ 11-1/2 months days ago
          'near future'           =>    132295.719, # ~ 1.5 days from now
        }.each do |desc, shift|
          shifted_now = timestamp - shift
          context "when that string could plausibly be in the #{desc} (NOW: #{shifted_now.iso8601(3)})" do
            let(:time_of_parse) { shifted_now }
            it "produces a time in the #{desc} (#{timestamp.iso8601(3)})" do
              expect(parsed_result).to eq(expected_result)
            end
          end
        end
      end
    end
  end
end
