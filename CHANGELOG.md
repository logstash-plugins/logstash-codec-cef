## 6.2.7
 - Fix: when decoding in an ecs_compatibility mode, timestamp-normalized fields now handle provided-but-empty values [#102](https://github.com/logstash-plugins/logstash-codec-cef/issues/102)

## 6.2.6
 - Fix: when decoding, escaped newlines and carriage returns in extension values are now correctly decoded into literal newlines and carriage returns respectively [#98](https://github.com/logstash-plugins/logstash-codec-cef/pull/98)
 - Fix: when decoding, non-CEF payloads are identified and intercepted to prevent data-loss and corruption. They now cause a descriptive log message to be emitted, and are emitted as their own `_cefparsefailure`-tagged event containing the original bytes in its `message` field [#99](https://github.com/logstash-plugins/logstash-codec-cef/issues/99)
 - Fix: when decoding while configured with a `delimiter`, flushing this codec now correctly consumes the remainder of its internal buffer. This resolves an issue where bytes that are written without a trailing delimiter could be lost [#100](https://github.com/logstash-plugins/logstash-codec-cef/issues/100) 

## 6.2.5
  - [DOC] Update link to CEF implementation guide [#97](https://github.com/logstash-plugins/logstash-codec-cef/pull/97)

## 6.2.4
  - [DOC] Emphasize importance of delimiter setting for byte stream inputs [#95](https://github.com/logstash-plugins/logstash-codec-cef/pull/95)

## 6.2.3
  - Feat: event_factory support [#94](https://github.com/logstash-plugins/logstash-codec-cef/pull/94)

## 6.2.2
 - Fixed invalid Field Reference that could occur when ECS mode was enabled and the CEF field `fileHash` was parsed.
 - Added expanded mapping for numbered `deviceCustom*` and `deviceCustom*Label` fields so that all now include numbers 1 through 15. [#89](https://github.com/logstash-plugins/logstash-codec-cef/pull/89).

## 6.2.1
 - Added field mapping to docs.
 - Fixed ECS mapping of `deviceMacAddress` field. [#88](https://github.com/logstash-plugins/logstash-codec-cef/pull/88).

## 6.2.0
 - Introduce ECS Compatibility mode [#83](https://github.com/logstash-plugins/logstash-codec-cef/pull/83).

## 6.1.2
 - Added error log with full payload when something bad happens in decoding a message [#84](https://github.com/logstash-plugins/logstash-codec-cef/pull/84)

## 6.1.1
 - Improved encoding performance, especially when encoding many extension fields [#81](https://github.com/logstash-plugins/logstash-codec-cef/pull/81)

## 6.1.0
 - Fixed CEF short to long name translation for ahost/agentHostName field, according to documentation [#75](https://github.com/logstash-plugins/logstash-codec-cef/pull/75)

## 6.0.1
 - Fixed support for deep dot notation [#73](https://github.com/logstash-plugins/logstash-codec-cef/pull/73)

## 6.0.0
 - Removed obsolete `sev` and `deprecated_v1_fields` fields

## 5.0.7
  - Fixed minor doc inconsistencies (added reverse_mapping to options table, moved it to alpha order in option descriptions, fixed typo)
  [#60](https://github.com/logstash-plugins/logstash-codec-cef/pull/60)

## 5.0.6
  - Added reverse_mapping option, which can be used to make encoder compliant to spec [#51](https://github.com/logstash-plugins/logstash-codec-cef/pull/51)

## 5.0.5
 - Fix handling of malformed inputs that have illegal unescaped-equals characters in extension field values (restores behaviour from <= v5.0.3 in some edge-cases) ([#56](https://github.com/logstash-plugins/logstash-codec-cef/issues/56))

## 5.0.4
 - Fix bug in parsing headers where certain legal escape sequences could cause non-escaped pipe characters to be ignored.
 - Fix bug in parsing extension values where a legal unescaped space in a field's value could be interpreted as a field separator (#54)
 - Add explicit handling for extension key names that use array-like syntax that isn't legal with the strict-mode field-reference parser (e.g., `fieldname[0]` becomes `[fieldname][0]`).

## 5.0.3
 - Fix handling of higher-plane UTF-8 characters in message body

## 5.0.2
  - Update gemspec summary

## 5.0.1
  - Fix some documentation issues

## 5.0.0
 - move `sev` and `deprecated_v1_fields` fields from deprecated to obsolete

## 4.1.2
 - added mapping for outcome = eventOutcome from CEF whitepaper (ref:p26/39)

## 4.1.1
 - changed rt from receiptTime to deviceReceiptTime (ref:p27/39)
 - changed tokenizer to include additional fields (ad.fieldname)

## 4.1.0
 - Add `delimiter` setting. This allows the decoder to be used with inputs like the TCP input where event delimiters are used.

## 4.0.0
 - Implements the dictionary translation for abbreviated CEF field names from chapter Chapter 2: ArcSight Extension Dictionary page 3 of 39 [CEF specification](https://protect724.hp.com/docs/DOC-1072).
 - add `_cefparsefailure` tag on failed decode

## 3.0.0
 - breaking: Updated plugin to use new Java Event APIs

## 2.1.3
 - Switch in-place sub! to sub when extracting `cef_version`. new Logstash Java Event does not support in-place String changes.

## 2.1.2
 - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.1.1
 - New dependency requirements for logstash-core for the 5.0 release

## 2.1.0
 - Implements `encode` with escaping according to the [CEF specification](https://protect724.hp.com/docs/DOC-1072).
 - Config option `sev` is deprecated, use `severity` instead.

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
