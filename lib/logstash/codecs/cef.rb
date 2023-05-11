# encoding: utf-8
require "logstash/util/buftok"
require "logstash/util/charset"
require "logstash/codecs/base"
require "json"
require "time"

require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'

# Implementation of a Logstash codec for the ArcSight Common Event Format (CEF)
# Based on Revision 20 of Implementing ArcSight CEF, dated from June 05, 2013
# https://community.saas.hpe.com/dcvta86296/attachments/dcvta86296/connector-documentation/1116/1/CommonEventFormatv23.pdf
#
# If this codec receives a payload from an input that is not a valid CEF message, then it will
# produce an event with the payload as the 'message' field and a '_cefparsefailure' tag.
class LogStash::Codecs::CEF < LogStash::Codecs::Base
  config_name "cef"

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter

  InvalidTimestamp = Class.new(StandardError)

  # Device vendor field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :vendor, :validate => :string, :default => "Elasticsearch"

  # Device product field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :product, :validate => :string, :default => "Logstash"

  # Device version field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :version, :validate => :string, :default => "1.0"

  # Signature ID field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :signature, :validate => :string, :default => "Logstash"

  # Name field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :name, :validate => :string, :default => "Logstash"

  # Severity field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  config :severity, :validate => :string, :default => "6"

  # Fields to be included in CEV extension part as key/value pairs
  config :fields, :validate => :array, :default => []
  
  # When encoding to CEF, set this to true to adhere to the specifications and
  # encode using the CEF key name (short name) for the CEF field names.
  # Defaults to false to preserve previous behaviour that was to use the long
  # version of the CEF field names.
  config :reverse_mapping, :validate => :boolean, :default => false

  # If your input puts a delimiter between each CEF event, you'll want to set
  # this to be that delimiter.
  #
  # For example, with the TCP input, you probably want to put this:
  #
  #     input {
  #       tcp {
  #         codec => cef { delimiter => "\r\n" }
  #         # ...
  #       }
  #     }
  #
  # This setting allows the following character sequences to have special meaning:
  #
  # * `\\r` (backslash "r") - means carriage return (ASCII 0x0D)
  # * `\\n` (backslash "n") - means newline (ASCII 0x0A)
  config :delimiter, :validate => :string

  # When parsing timestamps that do not include a UTC offset in payloads that do not
  # include the device's timezone, the default timezone is used.
  # If none is provided the system timezone is used.
  config :default_timezone, :validate => :string

  # The locale is used to parse abbreviated month names from some CEF timestamp
  # formats.
  # If none is provided, the system default is used.
  config :locale, :validate => :string

  # If raw_data_field is set, during decode of an event an additional field with
  # the provided name is added, which contains the raw data.
  config :raw_data_field, :validate => :string

  # Defines whether a set of device-specific CEF fields represent the _observer_,
  # or the actual `host` on which the event occurred. If this codec handles a mix,
  # it is safe to use the default `observer`.
  config :device, :validate => %w(observer host), :default => 'observer'

  # A CEF Header is a sequence of zero or more:
  #  - backslash-escaped pipes; OR
  #  - backslash-escaped backslashes; OR
  #  - non-pipe characters
  HEADER_PATTERN = /(?:\\\||\\\\|[^|])*?/

  # Cache of a scanner pattern that _captures_ a HEADER followed by EOF or an unescaped pipe
  HEADER_NEXT_FIELD_PATTERN = /(#{HEADER_PATTERN})#{Regexp.quote('|')}/

  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped pipe, _capturing_ the escaped character
  HEADER_ESCAPE_CAPTURE = /\\([\\|])/

  # While the original CEF spec calls out that extension keys must be alphanumeric and must not contain spaces,
  # in practice many "CEF" producers like the Arcsight smart connector produce non-legal keys including underscores,
  # commas, periods, and square-bracketed index offsets.
  #
  # To support this, we look for a specific sequence of characters that are followed by an equals sign. This pattern
  # will correctly identify all strictly-legal keys, and will also match those that include a dot-joined "subkeys" and
  # square-bracketed array indexing
  #
  # That sequence must begin with one or more `\w` (word: alphanumeric + underscore), which _optionally_ may be followed
  # by one or more "subkey" sequences and an optional square-bracketed index.
  #
  # To be understood by this implementation, a "subkey" sequence must consist of a literal dot (`.`) followed by one or
  # more characters that do not convey semantic meaning within CEF (e.g., literal-dot (`.`), literal-equals (`=`),
  # whitespace (`\s`), literal-pipe (`|`), literal-backslash ('\'), or literal-square brackets (`[` or `]`)).
  EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\.=\s\|\\\[\]]+)*(?:\[[0-9]+\])?(?==))/

  # Some CEF extension keys seen in the wild use an undocumented array-like syntax that may not be compatible with
  # the Event API's strict-mode FieldReference parser (e.g., `fieldname[0]`).
  # Cache of a `String#sub` pattern matching array-like syntax and capturing both the base field name and the
  # array-indexing portion so we can convert to a valid FieldReference (e.g., `[fieldname][0]`).
  EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/ # '[\1]\2'

  # In extensions, spaces may be included in an extension value without any escaping,
  # so an extension value is a sequence of zero or more:
  # - non-whitespace character; OR
  # - runs of whitespace that are NOT followed by something that looks like a key-equals sequence
  EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{EXTENSION_KEY_PATTERN}=))*/

  # Cache of a pattern that _captures_ the NEXT extension field key/value pair
  EXTENSION_NEXT_KEY_VALUE_PATTERN = /^(#{EXTENSION_KEY_PATTERN})=(#{EXTENSION_VALUE_PATTERN})\s*/

  ##
  # @see CEF#sanitize_header_field
  HEADER_FIELD_SANITIZER_MAPPING = {
    "\\" => "\\\\",
    "|"  => "\\|",
    "\n" => " ",
    "\r" => " ",
  }
  HEADER_FIELD_SANITIZER_PATTERN = Regexp.union(HEADER_FIELD_SANITIZER_MAPPING.keys)
  private_constant :HEADER_FIELD_SANITIZER_MAPPING, :HEADER_FIELD_SANITIZER_PATTERN

  ##
  # @see CEF#sanitize_extension_val
  EXTENSION_VALUE_SANITIZER_MAPPING = {
    "\\" => "\\\\",
    "="  => "\\=",
    "\n" => "\\n",
    "\r" => "\\n",
  }.freeze
  EXTENSION_VALUE_SANITIZER_PATTERN = Regexp.union(EXTENSION_VALUE_SANITIZER_MAPPING.keys)
  private_constant :EXTENSION_VALUE_SANITIZER_MAPPING, :EXTENSION_VALUE_SANITIZER_PATTERN


  LITERAL_BACKSLASH = "\\".freeze
  private_constant :LITERAL_BACKSLASH
  LITERAL_NEWLINE = "\n".freeze
  private_constant :LITERAL_NEWLINE
  LITERAL_CARRIAGE_RETURN = "\r".freeze
  private_constant :LITERAL_CARRIAGE_RETURN

  ##
  # @see CEF#desanitize_extension_val
  EXTENSION_VALUE_SANITIZER_REVERSE_MAPPING = {
    LITERAL_BACKSLASH+LITERAL_BACKSLASH => LITERAL_BACKSLASH,
    LITERAL_BACKSLASH+'=' => '=',
    LITERAL_BACKSLASH+'n' => LITERAL_NEWLINE,
    LITERAL_BACKSLASH+'r' => LITERAL_CARRIAGE_RETURN,
  }.freeze
  EXTENSION_VALUE_SANITIZER_REVERSE_PATTERN = Regexp.union(EXTENSION_VALUE_SANITIZER_REVERSE_MAPPING.keys)
  private_constant :EXTENSION_VALUE_SANITIZER_REVERSE_MAPPING, :EXTENSION_VALUE_SANITIZER_REVERSE_PATTERN


  CEF_PREFIX = 'CEF:'.freeze

  public
  def initialize(params={})
    super(params)

    # CEF input MUST be UTF-8, per the CEF White Paper that serves as the format's specification:
    # https://web.archive.org/web/20160422182529/https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    if @delimiter
      # Logstash configuration doesn't have built-in support for escaping,
      # so we implement it here. Feature discussion for escaping is here:
      #   https://github.com/elastic/logstash/issues/1645
      @delimiter = @delimiter.gsub("\\r", "\r").gsub("\\n", "\n")
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
    end

    require_relative 'cef/timestamp_normalizer'
    @timestamp_normalizer = TimestampNormalizer.new(locale: @locale, timezone: @default_timezone)

    generate_header_fields!
    generate_mappings!
  end

  public
  def decode(data, &block)
    if @delimiter
      @logger.trace("Buffering #{data.bytesize}B of data") if @logger.trace?
      @buffer.extract(data).each do |line|
        @logger.trace("Decoding #{line.bytesize + @delimiter.bytesize}B of buffered data") if @logger.trace?
        handle(line, &block)
      end
    else
      @logger.trace("Decoding #{data.bytesize}B of unbuffered data") if @logger.trace?
      handle(data, &block)
    end
  end

  def flush(&block)
    if @delimiter && (remainder = @buffer.flush)
      @logger.trace("Flushing #{remainder.bytesize}B of buffered data") if @logger.trace?
      handle(remainder, &block) unless remainder.empty?
    end
  end

  def handle(data, &block)
    original_data = data.dup
    event = event_factory.new_event
    event.set(raw_data_field, data) unless raw_data_field.nil?

    @utf8_charset.convert(data)

    # Several of the many operations in the rest of this method will fail when they encounter UTF8-tagged strings
    # that contain invalid byte sequences; fail early to avoid wasted work.
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Strip any quotations at the start and end, flex connectors seem to send this
    if data[0] == "\""
      data = data[1..-2]
    end

    # Use a scanning parser to capture the HEADER_FIELDS
    unprocessed_data = data.chomp
    if unprocessed_data.include?(LITERAL_NEWLINE)
      fail("message is not valid CEF because it contains unescaped newline characters; " +
           "use the `delimiter` setting to enable in-codec buffering and delimiter-splitting")
    end
    @header_fields.each_with_index do |field_name, idx|
      match_data = HEADER_NEXT_FIELD_PATTERN.match(unprocessed_data)
      if match_data.nil?
        fail("message is not valid CEF; found #{idx} of 7 required pipe-terminated header fields")
      end

      escaped_field_value = match_data[1]
      next if escaped_field_value.nil?

      # process legal header escape sequences
      unescaped_field_value = escaped_field_value.gsub(HEADER_ESCAPE_CAPTURE, '\1')

      event.set(field_name, unescaped_field_value)
      unprocessed_data = match_data.post_match
    end

    #Remainder is message
    message = unprocessed_data

    # Try and parse out the syslog header if there is one
    cef_version_field = @header_fields[0]
    if (cef_version = event.get(cef_version_field)).include?(' ')
      split_cef_version = cef_version.rpartition(' ')
      event.set(@syslog_header, split_cef_version[0])
      event.set(cef_version_field, split_cef_version[2])
    end

    # Get rid of the CEF bit in the version
    event.set(cef_version_field, delete_cef_prefix(event.get(cef_version_field)))

    # Use a scanning parser to capture the Extension Key/Value Pairs
    if message && !message.empty?
      message = message.strip
      extension_fields = {}

      while (match = message.match(EXTENSION_NEXT_KEY_VALUE_PATTERN))
        extension_field_key, raw_extension_field_value = match.captures
        message = match.post_match

        # expand abbreviated extension field keys
        extension_field_key = @decode_mapping.fetch(extension_field_key, extension_field_key)

        # convert extension field name to strict legal field_reference, fixing field names with ambiguous array-like syntax
        extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')

        # process legal extension field value escapes
        extension_field_value = desanitize_extension_val(raw_extension_field_value)

        extension_fields[extension_field_key] = extension_field_value
      end
      if !message.empty?
        fail("invalid extensions; keyless value present `#{message}`")
      end

      # in ECS mode, normalize timestamps including timezone.
      if ecs_compatibility != :disabled
        device_timezone = extension_fields['[event][timezone]']
        @timestamp_fields.each do |timestamp_field_name|
          raw_timestamp = extension_fields.delete(timestamp_field_name) or next
          value = normalize_timestamp(raw_timestamp, device_timezone)
          event.set(timestamp_field_name, value)
        end
      end

      extension_fields.each do |field_key, field_value|
        event.set(field_key, field_value)
      end
    end

    yield event
  rescue => e
    @logger.error("Failed to decode CEF payload. Generating failure event with payload in message field.",
                  log_metadata(:original_data => original_data))
    yield event_factory.new_event("message" => data, "tags" => ["_cefparsefailure"])
  end

  public
  def encode(event)
    # "CEF:0|Elasticsearch|Logstash|1.0|Signature|Name|Sev|"

    vendor = sanitize_header_field(event.sprintf(@vendor))
    vendor = self.class.get_config["vendor"][:default] if vendor.empty?

    product = sanitize_header_field(event.sprintf(@product))
    product = self.class.get_config["product"][:default] if product.empty?

    version = sanitize_header_field(event.sprintf(@version))
    version = self.class.get_config["version"][:default] if version.empty?

    signature = sanitize_header_field(event.sprintf(@signature))
    signature = self.class.get_config["signature"][:default] if signature.empty?

    name = sanitize_header_field(event.sprintf(@name))
    name = self.class.get_config["name"][:default] if name.empty?

    severity = sanitize_severity(event, @severity)

    # Should also probably set the fields sent
    header = ["CEF:0", vendor, product, version, signature, name, severity].join("|")
    values = @fields.map { |fieldname| get_value(fieldname, event) }.compact.join(" ")

    @on_event.call(event, "#{header}|#{values}#{@delimiter}")
  end

  private

  def generate_header_fields!
    # @header_fields is an _ordered_ set of fields.
    @header_fields = [
      ecs_select[disabled: 'cefVersion',         v1: '[cef][version]'],
      ecs_select[disabled: 'deviceVendor',       v1: '[observer][vendor]'],
      ecs_select[disabled: 'deviceProduct',      v1: '[observer][product]'],
      ecs_select[disabled: 'deviceVersion',      v1: '[observer][version]'],
      ecs_select[disabled: 'deviceEventClassId', v1: '[event][code]'],
      ecs_select[disabled: 'name',               v1: '[cef][name]'],
      ecs_select[disabled: 'severity',           v1: '[event][severity]']
    ].map(&:freeze).freeze
    # the @syslog_header is the field name used when a syslog header preceeds the CEF Version.
    @syslog_header = ecs_select[disabled:'syslog',v1:'[log][syslog][header]']
  end

  ##
  # produces log metadata, injecting the current exception and log-level-relevant backtraces
  # @param context [Hash{Symbol=>Object}]: the base context
  def log_metadata(context={})
    return context unless $!

    exception_context = {}
    exception_context[:exception] = "#{$!.class}: #{$!.message}"
    exception_context[:backtrace] = $!.backtrace if @logger.debug?

    exception_context.merge(context)
  end

  class CEFField
    ##
    # @param name [String]: the full CEF name of a field
    # @param key [String] (optional): an abbreviated CEF key to use when encoding a value with `reverse_mapping => true`
    #                                 when left unspecified, the `key` is the field's `name`.
    # @param ecs_field [String] (optional): an ECS-compatible field reference to use, with square-bracket syntax.
    #                                 when left unspecified, the `ecs_field` is the field's `name`.
    # @param legacy [String] (optional): a legacy CEF name to support in pass-through.
    #                                 in decoding mode without ECS, field name will be used as-provided.
    #                                 in encoding mode without ECS when provided to `fields` and `reverse_mapping => false`,
    #                                 field name will be used as-provided.
    # @param priority [Integer] (optional): when multiple fields resolve to the same ECS field name, the field with the
    #                                 highest `prioriry` will be used by the encoder.
    def initialize(name, key: name, ecs_field: name, legacy:nil, priority:0, normalize:nil)
      @name = name
      @key = key
      @ecs_field = ecs_field
      @legacy = legacy
      @priority = priority
      @normalize = normalize
    end
    attr_reader :name
    attr_reader :key
    attr_reader :ecs_field
    attr_reader :legacy
    attr_reader :priority
    attr_reader :normalize
  end

  def generate_mappings!
    encode_mapping = Hash.new
    decode_mapping = Hash.new
    timestamp_fields = Set.new
    [
      CEFField.new("agentAddress",                    key: "agt",       ecs_field: "[agent][ip]"),
      CEFField.new("agentDnsDomain",                                    ecs_field: "[cef][agent][registered_domain]", priority: 10),
      CEFField.new("agentHostName",                   key: "ahost",     ecs_field: "[agent][name]"),
      CEFField.new("agentId",                         key: "aid",       ecs_field: "[agent][id]"),
      CEFField.new("agentMacAddress",                 key: "amac",      ecs_field: "[agent][mac]"),
      CEFField.new("agentNtDomain",                                     ecs_field: "[cef][agent][registered_domain]"),
      CEFField.new("agentReceiptTime",                key: "art",       ecs_field: "[event][created]", normalize: :timestamp),
      CEFField.new("agentTimeZone",                   key: "atz",       ecs_field: "[cef][agent][timezone]"),
      CEFField.new("agentTranslatedAddress",                            ecs_field: "[cef][agent][nat][ip]"),
      CEFField.new("agentTranslatedZoneExternalID",                     ecs_field: "[cef][agent][translated_zone][external_id]"),
      CEFField.new("agentTranslatedZoneURI",                            ecs_field: "[cef][agent][translated_zone][uri]"),
      CEFField.new("agentType",                       key: "at",        ecs_field: "[agent][type]"),
      CEFField.new("agentVersion",                    key: "av",        ecs_field: "[agent][version]"),
      CEFField.new("agentZoneExternalID",                               ecs_field: "[cef][agent][zone][external_id]"),
      CEFField.new("agentZoneURI",                                      ecs_field: "[cef][agent][zone][uri]"),
      CEFField.new("applicationProtocol",             key: "app",       ecs_field: "[network][protocol]"),
      CEFField.new("baseEventCount",                  key: "cnt",       ecs_field: "[cef][base_event_count]"),
      CEFField.new("bytesIn",                         key: "in",        ecs_field: "[source][bytes]"),
      CEFField.new("bytesOut",                        key: "out",       ecs_field: "[destination][bytes]"),
      CEFField.new("categoryDeviceType",              key: "catdt",     ecs_field: "[cef][device_type]"),
      CEFField.new("customerExternalID",                                ecs_field: "[organization][id]"),
      CEFField.new("customerURI",                                       ecs_field: "[organization][name]"),
      CEFField.new("destinationAddress",              key: "dst",       ecs_field: "[destination][ip]"),
      CEFField.new("destinationDnsDomain",                              ecs_field: "[destination][registered_domain]", priority: 10),
      CEFField.new("destinationGeoLatitude",          key: "dlat",      ecs_field: "[destination][geo][location][lat]", legacy: "destinationLatitude"),
      CEFField.new("destinationGeoLongitude",         key: "dlong",     ecs_field: "[destination][geo][location][lon]", legacy: "destinationLongitude"),
      CEFField.new("destinationHostName",             key: "dhost",     ecs_field: "[destination][domain]"),
      CEFField.new("destinationMacAddress",           key: "dmac",      ecs_field: "[destination][mac]"),
      CEFField.new("destinationNtDomain",             key: "dntdom",    ecs_field: "[destination][registered_domain]"),
      CEFField.new("destinationPort",                 key: "dpt",       ecs_field: "[destination][port]"),
      CEFField.new("destinationProcessId",            key: "dpid",      ecs_field: "[destination][process][pid]"),
      CEFField.new("destinationProcessName",          key: "dproc",     ecs_field: "[destination][process][name]"),
      CEFField.new("destinationServiceName",                            ecs_field: "[destination][service][name]"),
      CEFField.new("destinationTranslatedAddress",                      ecs_field: "[destination][nat][ip]"),
      CEFField.new("destinationTranslatedPort",                         ecs_field: "[destination][nat][port]"),
      CEFField.new("destinationTranslatedZoneExternalID",               ecs_field: "[cef][destination][translated_zone][external_id]"),
      CEFField.new("destinationTranslatedZoneURI",                      ecs_field: "[cef][destination][translated_zone][uri]"),
      CEFField.new("destinationUserId",               key: "duid",      ecs_field: "[destination][user][id]"),
      CEFField.new("destinationUserName",             key: "duser",     ecs_field: "[destination][user][name]"),
      CEFField.new("destinationUserPrivileges",       key: "dpriv",     ecs_field: "[destination][user][group][name]"),
      CEFField.new("destinationZoneExternalID",                         ecs_field: "[cef][destination][zone][external_id]"),
      CEFField.new("destinationZoneURI",                                ecs_field: "[cef][destination][zone][uri]"),
      CEFField.new("deviceAction",                    key: "act",       ecs_field: "[event][action]"),
      CEFField.new("deviceAddress",                   key: "dvc",       ecs_field: "[#{@device}][ip]"),
      (1..15).map do |idx|
        [
          CEFField.new("deviceCustomFloatingPoint#{idx}",      key: "cfp#{idx}",      ecs_field: "[cef][device_custom_floating_point_#{idx}][value]"),
          CEFField.new("deviceCustomFloatingPoint#{idx}Label", key: "cfp#{idx}Label", ecs_field: "[cef][device_custom_floating_point_#{idx}][label]"),
          CEFField.new("deviceCustomIPv6Address#{idx}",        key: "c6a#{idx}",      ecs_field: "[cef][device_custom_ipv6_address_#{idx}][value]"),
          CEFField.new("deviceCustomIPv6Address#{idx}Label",   key: "c6a#{idx}Label", ecs_field: "[cef][device_custom_ipv6_address_#{idx}][label]"),
          CEFField.new("deviceCustomNumber#{idx}",             key: "cn#{idx}",       ecs_field: "[cef][device_custom_number_#{idx}][value]"),
          CEFField.new("deviceCustomNumber#{idx}Label",        key: "cn#{idx}Label",  ecs_field: "[cef][device_custom_number_#{idx}][label]"),
          CEFField.new("deviceCustomString#{idx}",             key: "cs#{idx}",       ecs_field: "[cef][device_custom_string_#{idx}][value]"),
          CEFField.new("deviceCustomString#{idx}Label",        key: "cs#{idx}Label",  ecs_field: "[cef][device_custom_string_#{idx}][label]"),
        ]
      end,
      CEFField.new("deviceDirection",                                   ecs_field: "[network][direction]"),
      CEFField.new("deviceDnsDomain",                                   ecs_field: "[#{@device}][registered_domain]", priority: 10),
      CEFField.new("deviceEventCategory",             key: "cat",       ecs_field: "[cef][category]"),
      CEFField.new("deviceExternalId",                                  ecs_field: (@device == 'host' ? "[host][id]" : "[observer][name]")),
      CEFField.new("deviceFacility",                                    ecs_field: "[log][syslog][facility][code]"),
      CEFField.new("deviceHostName",                  key: "dvchost",   ecs_field: (@device == 'host' ? '[host][name]' : '[observer][hostname]')),
      CEFField.new("deviceInboundInterface",                            ecs_field: "[observer][ingress][interface][name]"),
      CEFField.new("deviceMacAddress",                key: "dvcmac",    ecs_field: "[#{@device}][mac]"),
      CEFField.new("deviceNtDomain",                                    ecs_field: "[cef][nt_domain]"),
      CEFField.new("deviceOutboundInterface",                           ecs_field: "[observer][egress][interface][name]"),
      CEFField.new("devicePayloadId",                                   ecs_field: "[cef][payload_id]"),
      CEFField.new("deviceProcessId",                 key: "dvcpid",    ecs_field: "[process][pid]"),
      CEFField.new("deviceProcessName",                                 ecs_field: "[process][name]"),
      CEFField.new("deviceReceiptTime",               key: "rt",        ecs_field: "@timestamp", normalize: :timestamp),
      CEFField.new("deviceTimeZone",                  key: "dtz",       ecs_field: "[event][timezone]", legacy: "destinationTimeZone"),
      CEFField.new("deviceTranslatedAddress",                           ecs_field: "[host][nat][ip]"),
      CEFField.new("deviceTranslatedZoneExternalID",                    ecs_field: "[cef][translated_zone][external_id]"),
      CEFField.new("deviceTranslatedZoneURI",                           ecs_field: "[cef][translated_zone][uri]"),
      CEFField.new("deviceVersion",                                     ecs_field: "[observer][version]"),
      CEFField.new("deviceZoneExternalID",                              ecs_field: "[cef][zone][external_id]"),
      CEFField.new("deviceZoneURI",                                     ecs_field: "[cef][zone][uri]"),
      CEFField.new("endTime",                         key: "end",       ecs_field: "[event][end]", normalize: :timestamp),
      CEFField.new("eventId",                                           ecs_field: "[event][id]"),
      CEFField.new("eventOutcome",                    key: "outcome",   ecs_field: "[event][outcome]"),
      CEFField.new("externalId",                                        ecs_field: "[cef][external_id]"),
      CEFField.new("fileCreateTime",                                    ecs_field: "[file][created]"),
      CEFField.new("fileHash",                                          ecs_field: "[file][hash]"),
      CEFField.new("fileId",                                            ecs_field: "[file][inode]"),
      CEFField.new("fileModificationTime",                              ecs_field: "[file][mtime]", normalize: :timestamp),
      CEFField.new("fileName",                        key: "fname",     ecs_field: "[file][name]"),
      CEFField.new("filePath",                                          ecs_field: "[file][path]"),
      CEFField.new("filePermission",                                    ecs_field: "[file][group]"),
      CEFField.new("fileSize",                        key: "fsize",     ecs_field: "[file][size]"),
      CEFField.new("fileType",                                          ecs_field: "[file][extension]"),
      CEFField.new("managerReceiptTime",              key: "mrt",       ecs_field: "[event][ingested]", normalize: :timestamp),
      CEFField.new("message",                         key: "msg",       ecs_field: "[message]"),
      CEFField.new("oldFileCreateTime",                                 ecs_field: "[cef][old_file][created]", normalize: :timestamp),
      CEFField.new("oldFileHash",                                       ecs_field: "[cef][old_file][hash]"),
      CEFField.new("oldFileId",                                         ecs_field: "[cef][old_file][inode]"),
      CEFField.new("oldFileModificationTime",                           ecs_field: "[cef][old_file][mtime]", normalize: :timestamp),
      CEFField.new("oldFileName",                                       ecs_field: "[cef][old_file][name]"),
      CEFField.new("oldFilePath",                                       ecs_field: "[cef][old_file][path]"),
      CEFField.new("oldFilePermission",                                 ecs_field: "[cef][old_file][group]"),
      CEFField.new("oldFileSize",                                       ecs_field: "[cef][old_file][size]"),
      CEFField.new("oldFileType",                                       ecs_field: "[cef][old_file][extension]"),
      CEFField.new("rawEvent",                                          ecs_field: "[event][original]"),
      CEFField.new("Reason",                          key: "reason",    ecs_field: "[event][reason]"),
      CEFField.new("requestClientApplication",                          ecs_field: "[user_agent][original]"),
      CEFField.new("requestContext",                                    ecs_field: "[http][request][referrer]"),
      CEFField.new("requestCookies",                                    ecs_field: "[cef][request][cookies]"),
      CEFField.new("requestMethod",                                     ecs_field: "[http][request][method]"),
      CEFField.new("requestUrl",                      key: "request",   ecs_field: "[url][original]"),
      CEFField.new("sourceAddress",                   key: "src",       ecs_field: "[source][ip]"),
      CEFField.new("sourceDnsDomain",                                   ecs_field: "[source][registered_domain]", priority: 10),
      CEFField.new("sourceGeoLatitude",               key: "slat",      ecs_field: "[source][geo][location][lat]", legacy: "sourceLatitude"),
      CEFField.new("sourceGeoLongitude",              key: "slong",     ecs_field: "[source][geo][location][lon]", legacy: "sourceLongitude"),
      CEFField.new("sourceHostName",                  key: "shost",     ecs_field: "[source][domain]"),
      CEFField.new("sourceMacAddress",                key: "smac",      ecs_field: "[source][mac]"),
      CEFField.new("sourceNtDomain",                  key: "sntdom",    ecs_field: "[source][registered_domain]"),
      CEFField.new("sourcePort",                      key: "spt",       ecs_field: "[source][port]"),
      CEFField.new("sourceProcessId",                 key: "spid",      ecs_field: "[source][process][pid]"),
      CEFField.new("sourceProcessName",               key: "sproc",     ecs_field: "[source][process][name]"),
      CEFField.new("sourceServiceName",                                 ecs_field: "[source][service][name]"),
      CEFField.new("sourceTranslatedAddress",                           ecs_field: "[source][nat][ip]"),
      CEFField.new("sourceTranslatedPort",                              ecs_field: "[source][nat][port]"),
      CEFField.new("sourceTranslatedZoneExternalID",                    ecs_field: "[cef][source][translated_zone][external_id]"),
      CEFField.new("sourceTranslatedZoneURI",                           ecs_field: "[cef][source][translated_zone][uri]"),
      CEFField.new("sourceUserId",                    key: "suid",      ecs_field: "[source][user][id]"),
      CEFField.new("sourceUserName",                  key: "suser",     ecs_field: "[source][user][name]"),
      CEFField.new("sourceUserPrivileges",            key: "spriv",     ecs_field: "[source][user][group][name]"),
      CEFField.new("sourceZoneExternalID",                              ecs_field: "[cef][source][zone][external_id]"),
      CEFField.new("sourceZoneURI",                                     ecs_field: "[cef][source][zone][uri]"),
      CEFField.new("startTime",                       key: "start",     ecs_field: "[event][start]", normalize: :timestamp),
      CEFField.new("transportProtocol",               key: "proto",     ecs_field: "[network][transport]"),
      CEFField.new("type",                                              ecs_field: "[cef][type]"),
    ].flatten.sort_by(&:priority).each do |cef|
      field_name = ecs_select[disabled:cef.name, v1:cef.ecs_field]

      # whether the source is a cef_key or cef_name, normalize to field_name
      decode_mapping[cef.key]  = field_name
      decode_mapping[cef.name] = field_name

      # whether source is a cef_name or a field_name, normalize to target
      normalized_encode_target = @reverse_mapping ? cef.key : cef.name
      encode_mapping[field_name] = normalized_encode_target
      encode_mapping[cef.name]   = normalized_encode_target unless cef.name == field_name

      # if a field has an alias, normalize pass-through
      if cef.legacy
        decode_mapping[cef.legacy] = ecs_select[disabled:cef.legacy, v1:cef.ecs_field]
        encode_mapping[cef.legacy] = @reverse_mapping ? cef.key : cef.legacy
      end

      timestamp_fields << field_name if ecs_compatibility != :disabled && cef.normalize == :timestamp
    end

    @decode_mapping = decode_mapping.dup.freeze
    @encode_mapping = encode_mapping.dup.freeze
    @timestamp_fields = timestamp_fields.dup.freeze
  end

  # Escape pipes and backslashes in the header. Equal signs are ok.
  # Newlines are forbidden.
  def sanitize_header_field(value)
    value.to_s
         .gsub("\r\n", "\n")
         .gsub(HEADER_FIELD_SANITIZER_PATTERN, HEADER_FIELD_SANITIZER_MAPPING)
  end

  # Keys must be made up of a single word, with no spaces
  # must be alphanumeric
  def sanitize_extension_key(value)
    value.to_s
         .gsub(/[^a-zA-Z0-9]/, "")
  end

  # Escape equal signs in the extensions. Canonicalize newlines.
  # CEF spec leaves it up to us to choose \r or \n for newline.
  # We choose \n as the default.
  def sanitize_extension_val(value)
    value.to_s
         .gsub("\r\n", "\n")
         .gsub(EXTENSION_VALUE_SANITIZER_PATTERN, EXTENSION_VALUE_SANITIZER_MAPPING)
  end

  def desanitize_extension_val(value)
    value.to_s.gsub(EXTENSION_VALUE_SANITIZER_REVERSE_PATTERN, EXTENSION_VALUE_SANITIZER_REVERSE_MAPPING)
  end

  def normalize_timestamp(value, device_timezone_name)
    return nil if value.nil? || value.to_s.strip.empty?

    normalized = @timestamp_normalizer.normalize(value, device_timezone_name).iso8601(9)

    LogStash::Timestamp.new(normalized)
  rescue => e
    @logger.error("Failed to parse CEF timestamp value `#{value}` (#{e.message})")
    raise InvalidTimestamp.new("Not a valid CEF timestamp: `#{value}`")
  end

  def get_value(fieldname, event)
    val = event.get(fieldname)

    return nil if val.nil?

    key = @encode_mapping.fetch(fieldname, fieldname)
    key = sanitize_extension_key(key)

    case val
    when Array, Hash
      return "#{key}=#{sanitize_extension_val(val.to_json)}"
    when LogStash::Timestamp
      return "#{key}=#{val.to_s}"
    else
      return "#{key}=#{sanitize_extension_val(val)}"
    end
  end

  def sanitize_severity(event, severity)
    severity = sanitize_header_field(event.sprintf(severity)).strip
    severity = self.class.get_config["severity"][:default] unless valid_severity?(severity)
    severity.to_i.to_s
  end

  def valid_severity?(sev)
    f = Float(sev)
    # check if it's an integer or a float with no remainder
    # and if the value is between 0 and 10 (inclusive)
    (f % 1 == 0) && f.between?(0,10)
  rescue TypeError, ArgumentError
    false
  end

  if Gem::Requirement.new(">= 2.5.0").satisfied_by? Gem::Version.new(RUBY_VERSION)
    def delete_cef_prefix(cef_version)
      cef_version.delete_prefix(CEF_PREFIX)
    end
  else
    def delete_cef_prefix(cef_version)
      cef_version.start_with?(CEF_PREFIX) ? cef_version[CEF_PREFIX.length..-1] : cef_version
    end
  end
end
